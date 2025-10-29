import os
import sys
import json
import shlex
import subprocess
import tempfile
import random
import time
import re
import logging
import datetime
from pathlib import Path
import asyncio

# third-party
try:
    import aiosqlite
    import discord
    from discord.ext import commands
    from discord import app_commands
except Exception as e:
    print("Missing Python packages. Install: pip install -U discord.py aiosqlite")
    raise

# ---------------- Load config ----------------
CFG_PATH = "config.json"
if not os.path.exists(CFG_PATH):
    print("Create config.json first (see header of script).")
    sys.exit(1)

with open(CFG_PATH, "r") as f:
    cfg = json.load(f)

TOKEN = cfg.get("token")
ADMIN_IDS = set(cfg.get("admin_ids", []))
CLOUD_IMAGE = cfg.get("cloud_image_path")
DEFAULT_NET = cfg.get("default_network", "default")
VM_STORAGE_DIR = cfg.get("vm_storage_dir", "/var/lib/libvirt/images")
VM_DISK_FORMAT = cfg.get("vm_disk_format", "qcow2")
USE_CLOUD_LOCALDS = cfg.get("use_cloud_localds", False)
DB_PATH = cfg.get("db_path", "powerdev_vms.db")
LOG_FILE = cfg.get("log_file", "powerdev_bot.log")
AUDIT_CHANNEL_ID = cfg.get("audit_channel_id")  # optional

# ---------------- Logging ----------------
logger = logging.getLogger("powerdev-cockpit")
logger.setLevel(logging.INFO)
fh = logging.FileHandler(LOG_FILE)
fh.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger.addHandler(fh)
logger.addHandler(logging.StreamHandler())

# ---------------- Helpers ----------------
def run(cmd, capture=True, check=False, timeout=None):
    """Run shell command synchronously. Raises if check True and returncode != 0."""
    logger.debug(f"CMD: {cmd}")
    proc = subprocess.run(cmd, shell=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.PIPE if capture else None,
                          text=True, timeout=timeout)
    if check and proc.returncode != 0:
        raise RuntimeError(f"Command failed ({proc.returncode}): {cmd}\nSTDOUT:{proc.stdout}\nSTDERR:{proc.stderr}")
    return (proc.stdout or "").strip(), (proc.stderr or "").strip(), proc.returncode

def rand_port():
    return random.randint(20000, 65000)

def ensure_dir(p):
    Path(p).mkdir(parents=True, exist_ok=True)

# ---------------- Cloud-init templates ----------------
USER_DATA_TPL = """#cloud-config
preserve_hostname: False
hostname: {hostname}
manage_etc_hosts: true

users:
  - name: ubuntu
    sudo: ALL=(ALL) NOPASSWD:ALL
    groups: sudo
    shell: /bin/bash
{ssh_block}
    lock_passwd: true

package_update: true
package_upgrade: true

packages:
  - tmate
  - cloud-init

write_files:
  - path: /root/.tmate_out
    content: ""

runcmd:
  - [ bash, -lc, "echo '== cloud-init starting ==' > /dev/console" ]
  - [ bash, -lc, "nohup tmate -F 2>&1 | tee -a /root/.tmate_out /dev/console &" ]
  - [ bash, -lc, "echo 'tmate started' > /dev/console" ]
final_message: "Cloud-init finished"
"""

META_DATA_TPL = """instance-id: {hostname}
local-hostname: {hostname}
"""

def make_user_data(hostname, ssh_pubkey=None):
    ssh_block = ""
    if ssh_pubkey:
        ssh_block = "    ssh-authorized-keys:\n      - " + ssh_pubkey + "\n"
    return USER_DATA_TPL.format(hostname=hostname, ssh_block=ssh_block), META_DATA_TPL.format(hostname=hostname)

# ---------------- DB ----------------
async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
        CREATE TABLE IF NOT EXISTS vms (
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE,
            owner_id INTEGER,
            assigned_user_id INTEGER,
            created_at TEXT,
            ram INTEGER,
            cpu INTEGER,
            disk INTEGER,
            host_port INTEGER,
            guest_ip TEXT,
            status TEXT,
            tmate_urls TEXT
        )""")
        await db.execute("""
        CREATE TABLE IF NOT EXISTS sshkeys (
            id INTEGER PRIMARY KEY,
            user_id INTEGER,
            name TEXT,
            pubkey TEXT,
            created_at TEXT
        )""")
        await db.commit()

# ---------------- VM operations (best-effort) ----------------
def create_seed_iso(name, user_data, meta_data, out_iso):
    """Create cloud-init seed ISO using cloud-localds if available, else genisoimage."""
    tmpd = tempfile.mkdtemp(prefix=f"seed-{name}-")
    ud_path = os.path.join(tmpd, "user-data")
    md_path = os.path.join(tmpd, "meta-data")
    with open(ud_path, "w") as f: f.write(user_data)
    with open(md_path, "w") as f: f.write(meta_data)
    if USE_CLOUD_LOCALDS and shutil_which("cloud-localds"):
        cmd = f"cloud-localds {shlex.quote(out_iso)} {shlex.quote(ud_path)} {shlex.quote(md_path)}"
        run(cmd, check=True)
        return out_iso
    # fallback genisoimage / mkisofs
    if shutil_which("genisoimage") or shutil_which("mkisofs"):
        tool = shutil_which("genisoimage") or shutil_which("mkisofs")
        cmd = f"{tool} -output {shlex.quote(out_iso)} -volid cidata -joliet -rock {shlex.quote(ud_path)} {shlex.quote(md_path)}"
        run(cmd, check=True)
        return out_iso
    raise RuntimeError("No cloud-localds or genisoimage/mkisofs found on host")

def shutil_which(name):
    import shutil
    return shutil.which(name)

def create_disk(name, disk_gb):
    ensure_dir(VM_STORAGE_DIR)
    vm_disk = os.path.join(VM_STORAGE_DIR, f"{name}.qcow2")
    if not os.path.exists(CLOUD_IMAGE):
        raise RuntimeError(f"Cloud image not found at {CLOUD_IMAGE}")
    # create a copy-on-write image with backing file
    cmd = f"qemu-img create -f {VM_DISK_FORMAT} -b {shlex.quote(CLOUD_IMAGE)} -F qcow2 {shlex.quote(vm_disk)} {int(disk_gb)}G"
    run(cmd, check=True)
    return vm_disk

def virt_install(name, ram_mb, vcpus, disk_path, seed_iso, network=DEFAULT_NET):
    cmd = (
        "virt-install "
        f"--name {shlex.quote(name)} "
        f"--ram {int(ram_mb)} --vcpus {int(vcpus)} "
        f"--disk path={shlex.quote(disk_path)},format={VM_DISK_FORMAT} "
        f"--import "
        f"--disk path={shlex.quote(seed_iso)},device=cdrom "
        f"--noautoconsole "
        f"--os-variant ubuntu22.04 "
        f"--network network={shlex.quote(network)} "
        f"--graphics none "
        f"--timeout 300"
    )
    run(cmd, check=True, timeout=600)

def wait_running(name, timeout=240):
    start = time.time()
    while time.time() - start < timeout:
        out, err, rc = run(f"virsh dominfo {shlex.quote(name)} || true")
        if "State: running" in out:
            return True
        time.sleep(2)
    return False

def get_mac(name):
    out, _, _ = run(f"virsh dumpxml {shlex.quote(name)} || true")
    m = re.search(r"<mac address='([^']+)'", out)
    return m.group(1) if m else None

def guest_ip_by_mac(network, mac):
    out, _, _ = run(f"virsh net-dhcp-leases {shlex.quote(network)} || true")
    for line in out.splitlines():
        if mac.lower() in line.lower():
            parts = line.split()
            if parts:
                return parts[0]
    return None

def add_iptables_nat(hostport, guest_ip):
    # add DNAT rule
    run(f"iptables -t nat -A PREROUTING -p tcp --dport {int(hostport)} -j DNAT --to-destination {guest_ip}:22", check=True)
    # allow masquerade for packets
    run(f"iptables -t nat -A POSTROUTING -p tcp -d {guest_ip} --dport 22 -j MASQUERADE", check=True)

def remove_iptables_nat(hostport, guest_ip):
    # best-effort remove rules that match port and guest_ip
    run(f"iptables -t nat -D PREROUTING -p tcp --dport {int(hostport)} -j DNAT --to-destination {guest_ip}:22 || true")
    run(f"iptables -t nat -D POSTROUTING -p tcp -d {guest_ip} --dport 22 -j MASQUERADE || true")

def read_console_for_tmate(name, timeout=40):
    """Try to capture some console output using virsh console for 'timeout' seconds (best-effort)."""
    try:
        # Use timeout wrapper to limit runtime
        cmd = f"bash -lc 'timeout {int(timeout)} virsh console {shlex.quote(name)}'"
        out, err, rc = run(cmd, timeout=timeout+5)
        data = out + "\n" + err
    except Exception:
        data = ""
    # search for tmate connect lines (ssh:// or https:// or tmate.io)
    urls = re.findall(r"(https?://\S*tmate\.io/\S+|ssh://\S+|tmate:\/\/\S+|\b[0-9A-Za-z+/]{32,}\b)", data)
    return urls, data

# ---------------- Bot ----------------
intents = discord.Intents.default()
bot = commands.Bot(command_prefix="!", intents=intents, help_command=None)

START_TIME = time.time()

def is_admin_user(user_id):
    return user_id in ADMIN_IDS

async def audit_log(channel_bot, title, text):
    logger.info(f"AUDIT: {title} - {text}")
    if AUDIT_CHANNEL_ID:
        ch = bot.get_channel(AUDIT_CHANNEL_ID)
        if ch:
            try:
                await ch.send(f"**{title}**\n{text}")
            except Exception:
                logger.exception("Failed to send audit log message")

# ---------- Startup ----------
@bot.event
async def on_ready():
    logger.info(f"Bot ready: {bot.user} ({bot.user.id})")
    await init_db()
    try:
        await bot.tree.sync()
    except Exception:
        logger.exception("Failed to sync commands")
    # set presence
    try:
        await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="By PowerDev | !help"))
    except Exception:
        pass

# ---------- Utility DB helpers ----------
async def save_vm_record(name, owner_id, ram, cpu, disk, host_port, guest_ip, status, tmate_urls):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT OR REPLACE INTO vms (name, owner_id, assigned_user_id, created_at, ram, cpu, disk, host_port, guest_ip, status, tmate_urls)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (name, owner_id, None, datetime.datetime.utcnow().isoformat(), ram, cpu, disk, host_port, guest_ip, status, json.dumps(tmate_urls)))
        await db.commit()

async def delete_vm_record(name):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM vms WHERE name = ?", (name,))
        await db.commit()

async def set_vm_status(name, status, guest_ip=None, tmate_urls=None):
    async with aiosqlite.connect(DB_PATH) as db:
        q = "UPDATE vms SET status = ?"
        params = [status]
        if guest_ip is not None:
            q += ", guest_ip = ?"
            params.append(guest_ip)
        if tmate_urls is not None:
            q += ", tmate_urls = ?"
            params.append(json.dumps(tmate_urls))
        q += " WHERE name = ?"
        params.append(name)
        await db.execute(q, tuple(params))
        await db.commit()

async def assign_vm_to_user(name, user_id):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE vms SET assigned_user_id = ? WHERE name = ?", (user_id, name))
        await db.commit()

async def unassign_vm(name):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("UPDATE vms SET assigned_user_id = NULL WHERE name = ?", (name,))
        await db.commit()

async def get_vm(name):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT name, owner_id, assigned_user_id, created_at, ram, cpu, disk, host_port, guest_ip, status, tmate_urls FROM vms WHERE name = ?", (name,))
        r = await cur.fetchone()
        if not r:
            return None
        return {
            "name": r[0], "owner_id": r[1], "assigned_user_id": r[2], "created_at": r[3],
            "ram": r[4], "cpu": r[5], "disk": r[6], "host_port": r[7], "guest_ip": r[8],
            "status": r[9], "tmate_urls": json.loads(r[10]) if r[10] else []
        }

async def list_vms_all():
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT name, owner_id, assigned_user_id, created_at, ram, cpu, disk, host_port, guest_ip, status FROM vms ORDER BY id DESC")
        rows = await cur.fetchall()
        res = []
        for r in rows:
            res.append({
                "name": r[0], "owner_id": r[1], "assigned_user_id": r[2], "created_at": r[3],
                "ram": r[4], "cpu": r[5], "disk": r[6], "host_port": r[7], "guest_ip": r[8], "status": r[9]
            })
        return res

async def list_vms_for_user(user_id):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT name, owner_id, assigned_user_id, created_at, ram, cpu, disk, host_port, guest_ip, status FROM vms WHERE assigned_user_id = ? ORDER BY id DESC", (user_id,))
        rows = await cur.fetchall()
        res = []
        for r in rows:
            res.append({
                "name": r[0], "owner_id": r[1], "assigned_user_id": r[2], "created_at": r[3],
                "ram": r[4], "cpu": r[5], "disk": r[6], "host_port": r[7], "guest_ip": r[8], "status": r[9]
            })
        return res

# ---------- SSH key DB ----------
async def add_sshkey_for_user(user_id, name, pubkey):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("INSERT INTO sshkeys (user_id, name, pubkey, created_at) VALUES (?, ?, ?, ?)", (user_id, name, pubkey, datetime.datetime.utcnow().isoformat()))
        await db.commit()

async def remove_sshkey_for_user(user_id, name):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("DELETE FROM sshkeys WHERE user_id = ? AND name = ?", (user_id, name))
        await db.commit()

async def get_sshkeys_for_user(user_id):
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute("SELECT name, pubkey, created_at FROM sshkeys WHERE user_id = ?", (user_id,))
        rows = await cur.fetchall()
        return [{"name": r[0], "pubkey": r[1], "created_at": r[2]} for r in rows]

# ---------- Commands ----------
# Utility ephemeral reply if unauthorized
async def unauthorized(interaction):
    await interaction.response.send_message("❌ You are not authorized to use this command.", ephemeral=True)

# Slash: createvps (admin only)
@bot.tree.command(name="createvps", description="(Admin) Create a KVM VM with cloud-init, tmate and SSH forwarding")
@app_commands.describe(name="VM name", ram="RAM in MB", cpu="vCPUs", disk="Disk GB", hostport="Host port to forward to guest SSH (0=random)", sshkey="Optional SSH public key to add to ubuntu user")
async def createvps(interaction: discord.Interaction, name: str, ram: int = 2048, cpu: int = 1, disk: int = 10, hostport: int = 0, sshkey: str = None):
    await interaction.response.defer(ephemeral=True)
    if not is_admin_user(interaction.user.id):
        return await unauthorized(interaction)
    if not CLOUD_IMAGE or not os.path.exists(CLOUD_IMAGE):
        await interaction.followup.send("❌ Cloud image path not configured or file missing. Edit config.json", ephemeral=True)
        return
    if hostport == 0:
        hostport = rand_port()

    await interaction.followup.send(f"⏳ Creating VM `{name}` — this may take a while. Hostport: {hostport}", ephemeral=True)
    try:
        user_data, meta_data = make_user_data(name, ssh_pubkey=sshkey)
        seed_iso = f"/tmp/{name}-seed.iso"
        create_seed_iso(name, user_data, meta_data, seed_iso)
    except Exception as e:
        logger.exception("seed iso error")
        await interaction.followup.send(f"❌ Failed to create seed ISO: {e}", ephemeral=True)
        return

    try:
        disk_path = create_disk(name, disk)
    except Exception as e:
        logger.exception("disk create error")
        await interaction.followup.send(f"❌ Disk creation failed: {e}", ephemeral=True)
        return

    try:
        virt_install(name, ram, cpu, disk_path, seed_iso, network=DEFAULT_NET)
    except Exception as e:
        logger.exception("virt-install error")
        await interaction.followup.send(f"❌ virt-install failed: {e}", ephemeral=True)
        return

    # wait running
    if not wait_running(name, timeout=240):
        await interaction.followup.send("❌ VM did not start running in time.", ephemeral=True)
        return

    # get mac/ip and add iptables
    mac = get_mac(name)
    guest_ip = None
    if mac:
        for _ in range(12):
            guest_ip = guest_ip_by_mac(DEFAULT_NET, mac)
            if guest_ip:
                break
            time.sleep(3)

    if guest_ip:
        try:
            add_iptables_nat(hostport, guest_ip)
        except Exception as e:
            logger.exception("iptables add failed")
            await interaction.followup.send(f"⚠️ VM running but failed to add iptables NAT: {e}", ephemeral=True)
    else:
        await interaction.followup.send("⚠️ VM running but guest IP not found yet. Port forwarding not configured.", ephemeral=True)

    # try to read console for tmate
    tmate_urls = []
    console_excerpt = ""
    try:
        urls, console_text = read_console_for_tmate(name, timeout=30)
        tmate_urls = urls
        console_excerpt = console_text[-1200:]
    except Exception:
        pass

    # save DB
    await save_vm_record(name, interaction.user.id, ram, cpu, disk, hostport, guest_ip or "", "running", tmate_urls)

    # reply
    lines = [f"✅ VM **{name}** created."]
    if guest_ip:
        lines.append(f"- Guest IP: `{guest_ip}`")
    lines.append(f"- Host SSH (forwarded): `HOST:{hostport}` (ssh to host:{hostport})")
    if tmate_urls:
        lines.append("- tmate URLs found:")
        for u in tmate_urls:
            lines.append(f"  • `{u}`")
    else:
        lines.append("- tmate URL not found yet. Use `virsh console {name}` on host to inspect or wait a bit.")
        if console_excerpt:
            lines.append("\nConsole excerpt (last part):\n```\n" + console_excerpt + "\n```")
    await interaction.followup.send("\n".join(lines), ephemeral=True)
    await audit_log(bot, "VM Created", f"{name} by <@{interaction.user.id}> hostport={hostport} guest_ip={guest_ip} tmate_found={len(tmate_urls)>0}")

# Slash: deletevps (admin)
@bot.tree.command(name="deletevps", description="(Admin) Destroy VM, undefine and remove disk & iptables")
@app_commands.describe(name="VM name to delete")
async def deletevps(interaction: discord.Interaction, name: str):
    await interaction.response.defer(ephemeral=True)
    if not is_admin_user(interaction.user.id):
        return await unauthorized(interaction)
    # lookup DB to get host_port / guest_ip
    vm = await get_vm(name)
    if not vm:
        await interaction.followup.send("❌ VM record not found in DB.", ephemeral=True)
        return
    # confirm: we'll just proceed (ephemeral)
    await interaction.followup.send(f"⏳ Deleting VM `{name}` now.", ephemeral=True)
    # attempt to destroy domain
    try:
        run(f"virsh destroy {shlex.quote(name)} || true", check=False)
        run(f"virsh undefine {shlex.quote(name)} --remove-all-storage || true", check=False)
    except Exception as e:
        logger.exception("virsh delete error")
    # try remove disk file
    disk_file = os.path.join(VM_STORAGE_DIR, f"{name}.qcow2")
    try:
        if os.path.exists(disk_file):
            os.remove(disk_file)
    except Exception:
        logger.exception("disk remove failed")
    # cleanup iptables
    try:
        if vm.get("host_port") and vm.get("guest_ip"):
            remove_iptables_nat(vm["host_port"], vm["guest_ip"])
    except Exception:
        logger.exception("iptables cleanup failed")
    # remove DB record
    await delete_vm_record(name)
    await interaction.followup.send(f"✅ VM `{name}` removal attempted. Check host for leftover resources.", ephemeral=True)
    await audit_log(bot, "VM Deleted", f"{name} by <@{interaction.user.id}>")

# Slash: reinstallvps (admin) - basically delete & create with same name
@bot.tree.command(name="reinstallvps", description="(Admin) Reinstall VM (destroy and recreate with same name)")
@app_commands.describe(name="VM name", ram="RAM MB", cpu="vCPUs", disk="Disk GB", hostport="Host SSH port (0=random)", sshkey="Optional SSH public key")
async def reinstallvps(interaction: discord.Interaction, name: str, ram: int = 2048, cpu: int = 1, disk: int = 10, hostport: int = 0, sshkey: str = None):
    await interaction.response.defer(ephemeral=True)
    if not is_admin_user(interaction.user.id):
        return await unauthorized(interaction)
    # delete first
    await interaction.followup.send(f"⏳ Reinstall: deleting existing `{name}` (if any) and creating new.", ephemeral=True)
    # call delete flow
    try:
        run(f"virsh destroy {shlex.quote(name)} || true")
        run(f"virsh undefine {shlex.quote(name)} --remove-all-storage || true")
    except Exception:
        pass
    disk_file = os.path.join(VM_STORAGE_DIR, f"{name}.qcow2")
    try:
        if os.path.exists(disk_file):
            os.remove(disk_file)
    except Exception:
        pass
    # create new
    # reuse createvps code flow inline
    if hostport == 0:
        hostport = rand_port()
    try:
        user_data, meta_data = make_user_data(name, ssh_pubkey=sshkey)
        seed_iso = f"/tmp/{name}-seed.iso"
        create_seed_iso(name, user_data, meta_data, seed_iso)
        disk_path = create_disk(name, disk)
        virt_install(name, ram, cpu, disk_path, seed_iso, network=DEFAULT_NET)
    except Exception as e:
        logger.exception("reinstall create error")
        await interaction.followup.send(f"❌ Reinstall failed during creation: {e}", ephemeral=True)
        return
    # wait and detect ip, tmate
    if not wait_running(name, timeout=240):
        await interaction.followup.send("❌ New VM did not enter running state.", ephemeral=True)
        return
    mac = get_mac(name)
    guest_ip = None
    if mac:
        for _ in range(12):
            guest_ip = guest_ip_by_mac(DEFAULT_NET, mac)
            if guest_ip:
                break
            time.sleep(3)
    if guest_ip:
        try:
            add_iptables_nat(hostport, guest_ip)
        except Exception:
            pass
    tmate_urls = []
    try:
        urls, cons = read_console_for_tmate(name, timeout=30)
        tmate_urls = urls
    except Exception:
        pass
    await save_vm_record(name, interaction.user.id, ram, cpu, disk, hostport, guest_ip or "", "running", tmate_urls)
    await interaction.followup.send(f"✅ Reinstalled `{name}`. Host port: {hostport} Guest IP: {guest_ip or 'N/A'}", ephemeral=True)
    await audit_log(bot, "VM Reinstalled", f"{name} by <@{interaction.user.id}> guest_ip={guest_ip}")

# Slash: listvms
@bot.tree.command(name="listvms", description="List VMs (admin sees all; users see assigned only)")
async def listvms(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    if is_admin_user(interaction.user.id):
        rows = await list_vms_all()
        if not rows:
            await interaction.followup.send("No VMs recorded.", ephemeral=True); return
        embed = discord.Embed(title="All VMs (PowerDev Cockpit)", color=discord.Color.blue())
        for v in rows:
            embed.add_field(name=v["name"], value=f"Owner: <@{v['owner_id']}> Assigned: {('<@'+str(v['assigned_user_id'])+'>') if v['assigned_user_id'] else 'None'}\nIP: {v['guest_ip'] or 'N/A'} | hostport: {v['host_port']} | {v['ram']}MB {v['cpu']}cpu {v['disk']}GB\nStatus: {v['status']}", inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)
    else:
        rows = await list_vms_for_user(interaction.user.id)
        if not rows:
            await interaction.followup.send("You have no assigned VMs.", ephemeral=True)
            return
        txt = []
        for v in rows:
            txt.append(f"- **{v['name']}** | ip:{v['guest_ip'] or 'N/A'} | hostport:{v['host_port']} | {v['ram']}MB {v['cpu']}cpu {v['disk']}GB | {v['status']}")
        await interaction.followup.send("\n".join(txt), ephemeral=True)

# Slash: myvps
@bot.tree.command(name="myvps", description="Show VMs assigned to you")
async def myvps(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    rows = await list_vms_for_user(interaction.user.id)
    if not rows:
        await interaction.followup.send("You have no assigned VMs.", ephemeral=True); return
    txt = []
    for v in rows:
        txt.append(f"- **{v['name']}** | ip:{v['guest_ip'] or 'N/A'} | hostport:{v['host_port']} | {v['ram']}MB {v['cpu']}CPU {v['disk']}GB | {v['status']}")
    await interaction.followup.send("\n".join(txt), ephemeral=True)

# Slash: assignvps (admin)
@bot.tree.command(name="assignvps", description="(Admin) Assign a VM to a user")
@app_commands.describe(name="VM name", user="Discord user to assign")
async def assignvps(interaction: discord.Interaction, name: str, user: discord.Member):
    await interaction.response.defer(ephemeral=True)
    if not is_admin_user(interaction.user.id):
        return await unauthorized(interaction)
    vm = await get_vm(name)
    if not vm:
        await interaction.followup.send("VM not found.", ephemeral=True); return
    await assign_vm_to_user(name, user.id)
    await interaction.followup.send(f"✅ Assigned `{name}` to <@{user.id}>", ephemeral=True)
    await audit_log(bot, "VM Assigned", f"{name} -> <@{user.id}> by <@{interaction.user.id}>")

# Slash: unassignvps (admin)
@bot.tree.command(name="unassignvps", description="(Admin) Unassign a VM")
@app_commands.describe(name="VM name")
async def unassignvps(interaction: discord.Interaction, name: str):
    await interaction.response.defer(ephemeral=True)
    if not is_admin_user(interaction.user.id):
        return await unauthorized(interaction)
    await unassign_vm(name)
    await interaction.followup.send(f"✅ Unassigned `{name}`", ephemeral=True)
    await audit_log(bot, "VM Unassigned", f"{name} by <@{interaction.user.id}>")

# Slash: vpsinfo
@bot.tree.command(name="vpsinfo", description="Show detailed info about a VM (admin sees any, user sees assigned only)")
@app_commands.describe(name="VM name")
async def vpsinfo(interaction: discord.Interaction, name: str):
    await interaction.response.defer(ephemeral=True)
    vm = await get_vm(name)
    if not vm:
        await interaction.followup.send("VM not found.", ephemeral=True); return
    # permission
    if not is_admin_user(interaction.user.id) and vm.get("assigned_user_id") != interaction.user.id:
        return await unauthorized(interaction)
    embed = discord.Embed(title=f"VPS Info: {name}", color=discord.Color.gold())
    embed.add_field(name="Owner", value=f"<@{vm['owner_id']}>", inline=True)
    embed.add_field(name="Assigned", value=(f"<@{vm['assigned_user_id']}>" if vm['assigned_user_id'] else "None"), inline=True)
    embed.add_field(name="Status", value=vm['status'] or "N/A", inline=True)
    embed.add_field(name="Guest IP", value=vm['guest_ip'] or "N/A", inline=True)
    embed.add_field(name="HostPort", value=str(vm['host_port']), inline=True)
    embed.add_field(name="Resources", value=f"{vm['ram']}MB RAM | {vm['cpu']} CPU | {vm['disk']}GB", inline=True)
    if vm.get("tmate_urls"):
        embed.add_field(name="tmate", value="\n".join(vm['tmate_urls']), inline=False)
    embed.set_footer(text=f"Created: {vm['created_at']}")
    await interaction.followup.send(embed=embed, ephemeral=True)

# Slash: startvps / stopvps / restartvps (users can manage their assigned VM)
@bot.tree.command(name="startvps", description="Start an assigned VM")
@app_commands.describe(name="VM name")
async def startvps(interaction: discord.Interaction, name: str):
    await interaction.response.defer(ephemeral=True)
    vm = await get_vm(name)
    if not vm:
        await interaction.followup.send("VM not found.", ephemeral=True); return
    if not is_admin_user(interaction.user.id) and vm.get("assigned_user_id") != interaction.user.id:
        return await unauthorized(interaction)
    try:
        run(f"virsh start {shlex.quote(name)} || true")
        await set_vm_status(name, "running")
        await interaction.followup.send(f"✅ Start requested for `{name}`", ephemeral=True)
        await audit_log(bot, "VM Start", f"{name} by <@{interaction.user.id}>")
    except Exception as e:
        logger.exception("startvps error")
        await interaction.followup.send(f"❌ Start failed: {e}", ephemeral=True)

@bot.tree.command(name="stopvps", description="Shutdown an assigned VM gracefully")
@app_commands.describe(name="VM name")
async def stopvps(interaction: discord.Interaction, name: str):
    await interaction.response.defer(ephemeral=True)
    vm = await get_vm(name)
    if not vm:
        await interaction.followup.send("VM not found.", ephemeral=True); return
    if not is_admin_user(interaction.user.id) and vm.get("assigned_user_id") != interaction.user.id:
        return await unauthorized(interaction)
    try:
        run(f"virsh shutdown {shlex.quote(name)} || true")
        await set_vm_status(name, "shutting-down")
        await interaction.followup.send(f"✅ Shutdown requested for `{name}`", ephemeral=True)
        await audit_log(bot, "VM Shutdown", f"{name} by <@{interaction.user.id}>")
    except Exception as e:
        logger.exception("stopvps error")
        await interaction.followup.send(f"❌ Shutdown failed: {e}", ephemeral=True)

@bot.tree.command(name="restartvps", description="Reboot an assigned VM")
@app_commands.describe(name="VM name")
async def restartvps(interaction: discord.Interaction, name: str):
    await interaction.response.defer(ephemeral=True)
    vm = await get_vm(name)
    if not vm:
        await interaction.followup.send("VM not found.", ephemeral=True); return
    if not is_admin_user(interaction.user.id) and vm.get("assigned_user_id") != interaction.user.id:
        return await unauthorized(interaction)
    try:
        run(f"virsh reboot {shlex.quote(name)} || true")
        await set_vm_status(name, "rebooting")
        await interaction.followup.send(f"✅ Reboot requested for `{name}`", ephemeral=True)
        await audit_log(bot, "VM Reboot", f"{name} by <@{interaction.user.id}>")
    except Exception as e:
        logger.exception("restartvps error")
        await interaction.followup.send(f"❌ Reboot failed: {e}", ephemeral=True)

# Slash: addsshkey / removesshkey
@bot.tree.command(name="addsshkey", description="Add an SSH public key to your account (stored; applied on create or via admin apply)")
@app_commands.describe(name="A short name for this key", pubkey="Your SSH public key string (ssh-rsa ...)")
async def addsshkey(interaction: discord.Interaction, name: str, pubkey: str):
    await interaction.response.defer(ephemeral=True)
    # store key
    try:
        await add_sshkey_for_user(interaction.user.id, name, pubkey)
        await interaction.followup.send(f"✅ SSH key `{name}` stored for <@{interaction.user.id}>. It will be used when you create a VM or when an admin runs /applykeys to inject into an existing VM.", ephemeral=True)
        await audit_log(bot, "SSH Key Added", f"user=<@{interaction.user.id}> name={name}")
    except Exception as e:
        logger.exception("addsshkey error")
        await interaction.followup.send(f"❌ Failed to store key: {e}", ephemeral=True)

@bot.tree.command(name="removesshkey", description="Remove a stored SSH public key")
@app_commands.describe(name="Key name to remove")
async def removesshkey(interaction: discord.Interaction, name: str):
    await interaction.response.defer(ephemeral=True)
    try:
        await remove_sshkey_for_user(interaction.user.id, name)
        await interaction.followup.send(f"✅ SSH key `{name}` removed for <@{interaction.user.id}>", ephemeral=True)
        await audit_log(bot, "SSH Key Removed", f"user=<@{interaction.user.id}> name={name}")
    except Exception as e:
        logger.exception("removesshkey error")
        await interaction.followup.send(f"❌ Failed: {e}", ephemeral=True)

# Admin: applykeys -> tries to inject stored keys into running VM via SSH (best-effort) or by recreating seed ISO if forced
@bot.tree.command(name="applykeys", description="(Admin) Attempt to inject stored SSH keys into a VM (best-effort via SSH to host:port). Requires credentials or access.")
@app_commands.describe(vmname="VM name", user_private_key="Optional path on host to private key to attempt SSH (host must allow)", ssh_user="SSH username to use (default: ubuntu)")
async def applykeys(interaction: discord.Interaction, vmname: str, user_private_key: str = None, ssh_user: str = "ubuntu"):
    await interaction.response.defer(ephemeral=True)
    if not is_admin_user(interaction.user.id):
        return await unauthorized(interaction)
    vm = await get_vm(vmname)
    if not vm:
        await interaction.followup.send("VM not found", ephemeral=True); return
    keys = await get_sshkeys_for_user(vm.get("assigned_user_id") or vm.get("owner_id"))
    if not keys:
        await interaction.followup.send("No stored SSH keys for that user.", ephemeral=True); return
    # try SSH to host:hostport and append to ~/.ssh/authorized_keys
    hostport = vm.get("host_port")
    if not hostport:
        await interaction.followup.send("VM has no host_port configured.", ephemeral=True); return
    # build authorized keys content
    content = "\n".join([k["pubkey"] for k in keys]) + "\n"
    # try to use ssh (host must allow connection). We will use ssh-copy-id-like approach using ssh with provided private key if given.
    ssh_cmd = None
    # Use plain ssh with Inline command to append to authorized_keys (best-effort)
    if user_private_key and os.path.exists(user_private_key):
        ssh_cmd = f"ssh -i {shlex.quote(user_private_key)} -o StrictHostKeyChecking=no -p {int(hostport)} {shlex.quote(ssh_user)}@localhost \"mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys\""
    else:
        # attempt without key (may fail)
        ssh_cmd = f"ssh -o StrictHostKeyChecking=no -p {int(hostport)} {shlex.quote(ssh_user)}@localhost \"mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys\""
    try:
        # open subprocess and send content to stdin
        p = subprocess.Popen(ssh_cmd, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = p.communicate(input=content, timeout=30)
        if p.returncode == 0:
            await interaction.followup.send("✅ Keys applied via SSH to VM (best-effort).", ephemeral=True)
            await audit_log(bot, "ApplyKeys", f"{vmname} keys applied by <@{interaction.user.id}>")
        else:
            await interaction.followup.send(f"⚠️ SSH apply failed (return {p.returncode}). Error: {err[:800]}", ephemeral=True)
    except Exception as e:
        logger.exception("applykeys ssh error")
        await interaction.followup.send(f"❌ Failed to apply keys via SSH: {e}", ephemeral=True)

# Slash: ping
@bot.tree.command(name="ping", description="Show bot latency")
async def ping_cmd(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    latency_ms = round(bot.latency * 1000)
    await interaction.followup.send(f"🏓 Pong — latency: {latency_ms} ms", ephemeral=True)

# Botinfo
@bot.tree.command(name="botinfo", description="Show bot info (Made by PowerDev)")
async def botinfo(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    uptime = int(time.time() - START_TIME)
    up_str = str(datetime.timedelta(seconds=uptime))
    embed = discord.Embed(title="PowerDev Cockpit Bot", color=discord.Color.green())
    embed.add_field(name="Made by", value="PowerDev", inline=True)
    embed.add_field(name="Uptime", value=up_str, inline=True)
    embed.add_field(name="Help", value="Type `!help` or use slash commands.", inline=False)
    embed.set_footer(text="Watching By PowerDev | !help")
    await interaction.followup.send(embed=embed, ephemeral=True)

# Text command: !help
@bot.command(name="help")
async def help_cmd(ctx: commands.Context):
    help_text = (
        "__**PowerDev Cockpit Bot — Help**__\n"
        "Admin commands (slash): /createvps /deletevps /reinstallvps /assignvps /unassignvps /applykeys /listvms /botinfo /ping\n"
        "User commands (slash): /myvps /listvms /vpsinfo /startvps /stopvps /restartvps /addsshkey /removesshkey\n"
        "Text commands: !help\n\n"
        "Note: Many operations require host privileges (virt-install/virsh/iptables). Run the bot as root or configure sudoers.\n"
        "Bot presence shows: Watching By PowerDev | !help\n"
    )
    await ctx.send(help_text)

# Error handler for app commands
@bot.event
async def on_app_command_error(interaction: discord.Interaction, error):
    logger.exception("app command error")
    try:
        await interaction.response.send_message(f"Error: {error}", ephemeral=True)
    except Exception:
        pass

# ---------------- Main ----------------
if __name__ == "__main__":
    if not TOKEN or TOKEN.startswith("<"):
        print("Set your bot token in config.json")
        sys.exit(1)
    # ensure DB init before running
    import asyncio as _asyncio
    _asyncio.get_event_loop().run_until_complete(init_db())
    try:
        bot.run(TOKEN)
    except Exception:
        logger.exception("Bot terminated")
