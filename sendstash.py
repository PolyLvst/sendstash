#!/usr/bin/env python3
import os
import sys
import yaml
import subprocess
import argparse
import tempfile
import re
import platform
import shutil
import glob as globmod
from datetime import datetime, timedelta


class SendStash:
    def __init__(self, config_path=None):
        self.config_path = self._find_config_file(config_path)
        if not self.config_path:
            print("Error: Could not find config.yaml.")
            print("Please place it in one of the documented locations")
            sys.exit(1)

        print(f"Loading config from: {self.config_path}")
        self.config = self._load_config(self.config_path)
        self.project_path = None

    def _find_config_file(self, specified_path):
        """Finds the config file in a prioritized list of locations."""
        if specified_path and os.path.exists(specified_path):
            return specified_path

        # Path specified by environment variable
        env_path = os.getenv('SENDSTASH_CONFIG_PATH')
        if env_path and os.path.exists(env_path):
            return env_path

        # User-specific config directory
        user_config_path = os.path.expanduser("~/.config/sendstash/config.yaml")
        if os.path.exists(user_config_path):
            return user_config_path

        # In an adjacent directory: ../sendstash-config/config.yaml
        script_dir = os.path.dirname(os.path.realpath(__file__))
        adjacent_config_path = os.path.join(script_dir, '..', 'sendstash-config', 'config.yaml')
        if os.path.exists(adjacent_config_path):
            return os.path.normpath(adjacent_config_path)

        # In the same directory as the script
        script_config_path = os.path.join(script_dir, 'config.yaml')
        if os.path.exists(script_config_path):
            return script_config_path

        return None

    def _load_config(self, config_path):
        """Loads the configuration from a YAML file."""
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)

        # Resolve password from password_cmd if needed
        smb = config.get('smb', {})
        if 'password_cmd' in smb and 'password' not in smb:
            try:
                result = subprocess.run(
                    smb['password_cmd'], shell=True,
                    capture_output=True, text=True, check=True
                )
                smb['password'] = result.stdout.strip()
            except subprocess.CalledProcessError as e:
                print(f"Error running password_cmd: {e}")
                sys.exit(1)

        # Expand project paths
        root = os.path.expanduser(config.get('root', ''))
        if 'projects' in config:
            for name, project in config['projects'].items():
                project['path'] = os.path.expanduser(project['path'].format(root=root))

        return config

    def get_project_choices(self):
        """Returns a list of project names from the config."""
        return list(self.config.get('projects', {}).keys())

    def set_project(self, project_name):
        """Set the working directory to a configured project's path."""
        projects = self.config.get('projects', {})
        if project_name not in projects:
            print(f"Error: Project '{project_name}' not found in config.")
            print(f"Available projects: {', '.join(projects.keys())}")
            sys.exit(1)
        self.project_path = projects[project_name]['path']
        if not os.path.isdir(self.project_path):
            print(f"Error: Project path does not exist: {self.project_path}")
            sys.exit(1)
        print(f"Using project: {project_name} ({self.project_path})")

    def _run_command(self, command, cwd=None, interactive=False, capture=False, env=None):
        """Runs a command and streams its output."""
        if capture:
            result = subprocess.run(
                command, cwd=cwd, shell=isinstance(command, str),
                capture_output=True, text=True, env=env
            )
            return result
        elif interactive:
            process = subprocess.Popen(command, cwd=cwd, shell=isinstance(command, str), env=env)
            process.wait()
            return process.returncode
        else:
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                universal_newlines=True, cwd=cwd, shell=isinstance(command, str), env=env
            )
            for line in process.stdout:
                print(line, end='')
            process.wait()
            return process.returncode

    def sync_config(self):
        """Syncs the configuration file itself based on 'config_sync' settings."""
        if 'config_sync' not in self.config:
            print("Warning: --sync-config was passed, but 'config_sync' section is not defined in config.yaml.")
            return

        sync_settings = self.config['config_sync']
        command = sync_settings.get('command')

        if not command:
            print("Error: 'config_sync' section is missing the 'command' key.")
            return

        config_dir = os.path.dirname(self.config_path)

        print(f"Syncing configuration using command: '{command}' in '{config_dir}'")
        return_code = self._run_command(command, cwd=config_dir)

        if return_code == 0:
            print("Configuration sync completed successfully.")
            print("Reloading configuration...")
            self.config = self._load_config(self.config_path)
        else:
            print(f"Configuration sync failed with return code: {return_code}")
            sys.exit(1)

    def open_folder(self):
        """Opens the sendstash script directory in the file explorer."""
        script_dir = os.path.dirname(os.path.realpath(__file__))

        print(f"Opening SendStash directory: {script_dir}")

        try:
            if sys.platform == "win32":
                subprocess.run(['explorer', script_dir], check=True)
            elif sys.platform == "darwin":
                subprocess.run(['open', script_dir], check=True)
            elif sys.platform == "linux":
                file_managers = ['xdg-open', 'nautilus', 'dolphin', 'thunar', 'nemo', 'pcmanfm']
                opened = False

                for fm in file_managers:
                    try:
                        subprocess.run([fm, script_dir], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        opened = True
                        break
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        continue

                if not opened:
                    print("Could not find a suitable file manager. Directory path:")
                    print(f"  {script_dir}")
                    return
            else:
                print(f"Unsupported platform: {sys.platform}")
                print(f"SendStash directory: {script_dir}")
                return

        except subprocess.CalledProcessError as e:
            print(f"Error opening folder: {e}")
            print(f"SendStash directory: {script_dir}")
        except Exception as e:
            print(f"Unexpected error: {e}")
            print(f"SendStash directory: {script_dir}")

    def _get_cwd(self):
        """Get the working directory — project path if set, otherwise current dir."""
        return self.project_path or None

    def _get_repo_name(self):
        """Derive repo name from current git repo's root directory name."""
        result = self._run_command('git rev-parse --show-toplevel', cwd=self._get_cwd(), capture=True)
        if result.returncode != 0:
            print("Error: Not inside a git repository.")
            sys.exit(1)
        return os.path.basename(result.stdout.strip())

    def _get_branch_name(self):
        """Get the current branch name."""
        result = self._run_command('git rev-parse --abbrev-ref HEAD', cwd=self._get_cwd(), capture=True)
        if result.returncode != 0:
            print("Error: Could not determine current branch.")
            sys.exit(1)
        return result.stdout.strip()

    def _sanitize_name(self, name):
        """Sanitize a name for use in filenames (replace / with _)."""
        return re.sub(r'[/\\]', '_', name)

    def _sanitize_for_filename(self, text, max_len=40):
        """Sanitize arbitrary text for use in a filename component."""
        # Replace whitespace and unsafe chars with hyphens, collapse runs, strip edges
        sanitized = re.sub(r'[^\w.-]+', '-', text).strip('-')
        return sanitized[:max_len].rstrip('-')

    def _smb_cmd(self, subcmd):
        """Build and run an smbclient command with auth from config."""
        smb = self.config['smb']
        server = smb['server']
        username = smb['username']
        password = smb['password']

        cmd = ['smbclient', server, '-U', f'{username}%{password}', '-c', subcmd]
        return subprocess.run(cmd, capture_output=True, text=True)

    def _get_remote_dir(self):
        """Get the base remote directory from config."""
        return self.config['smb'].get('remote_dir', 'stash-sync')

    def _detect_backend(self):
        """Detect whether to use mount-based I/O or smbclient."""
        if hasattr(self, '_backend'):
            return self._backend, self._mount_root

        smb = self.config['smb']

        # 1. Explicit mount_path in config
        mount_path = smb.get('mount_path')
        if mount_path:
            mount_path = os.path.expanduser(mount_path)
            if os.path.exists(mount_path):
                self._backend = 'mount'
                self._mount_root = mount_path
                return self._backend, self._mount_root
            else:
                print(f"Warning: Configured mount_path '{mount_path}' does not exist.")

        server = smb.get('server', '')
        # Parse //server/share into components
        parts = server.replace('\\', '/').strip('/').split('/')
        if len(parts) < 2:
            self._backend = 'smbclient'
            self._mount_root = None
            return self._backend, self._mount_root

        host, share = parts[0], parts[1]
        system = platform.system()
        is_wsl = False

        if system == 'Linux':
            try:
                with open('/proc/version', 'r') as f:
                    proc_version = f.read()
                if 'microsoft' in proc_version.lower():
                    is_wsl = True
            except (OSError, IOError):
                pass

        # 2. Auto-detect existing mounts
        if system == 'Windows':
            unc_path = f'\\\\{host}\\{share}'
            if os.path.exists(unc_path):
                self._backend = 'mount'
                self._mount_root = unc_path
                return self._backend, self._mount_root
        elif is_wsl:
            mnt_path = f'/mnt/{host}/{share}'
            if os.path.exists(mnt_path):
                self._backend = 'mount'
                self._mount_root = mnt_path
                return self._backend, self._mount_root

        # 3. Attempt auto-mount on Windows/WSL
        if system == 'Windows' or is_wsl:
            mount_result = self._ensure_mount(host, share, is_wsl)
            self._backend = 'mount'
            self._mount_root = mount_result
            return self._backend, self._mount_root

        # 4. Native Linux — fall back to smbclient
        self._backend = 'smbclient'
        self._mount_root = None
        return self._backend, self._mount_root

    def _ensure_mount(self, host, share, is_wsl):
        """Attempt to auto-mount the SMB share on Windows/WSL. Exits on failure."""
        smb = self.config['smb']
        username = smb.get('username', '')
        password = smb.get('password', '')

        if is_wsl:
            unc = f'\\\\\\\\{host}\\\\{share}'
            cmd = [
                'powershell.exe', '-Command',
                f'net use {unc} /user:{username} {password}'
            ]
            mount_path = f'/mnt/{host}/{share}'
        else:
            # Native Windows
            unc = f'\\\\{host}\\{share}'
            cmd = ['net', 'use', unc, f'/user:{username}', password]
            mount_path = unc

        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0 and os.path.exists(mount_path):
                print(f"Auto-mounted SMB share at: {mount_path}")
                return mount_path
        except (OSError, FileNotFoundError):
            pass

        print("Error: Could not auto-mount the SMB share.")
        if is_wsl:
            print(f"  Try manually: powershell.exe -Command \"net use \\\\\\\\{host}\\\\{share} /user:{username} <password>\"")
            print(f"  Or: sudo mount -t cifs //{host}/{share} /mnt/{host}/{share} -o username={username},password=<password>")
        else:
            print(f"  Try manually: net use \\\\{host}\\{share} /user:{username} <password>")
        print("  Or set 'mount_path' in your config.yaml to the mount point.")
        sys.exit(1)

    def _get_share_path(self, *parts):
        """Return the full local path to a file/dir on the mounted share."""
        return os.path.join(self._mount_root, self._get_remote_dir(), *parts)

    def _list_patches_raw(self, repo_name):
        """List patches on the share. Returns [(name, size, date), ...] sorted by name."""
        backend, _ = self._detect_backend()

        if backend == 'mount':
            share_dir = self._get_share_path(repo_name)
            if not os.path.isdir(share_dir):
                return []
            patch_files = globmod.glob(os.path.join(share_dir, '*.patch'))
            patches = []
            for path in patch_files:
                name = os.path.basename(path)
                stat = os.stat(path)
                size = str(stat.st_size)
                date = datetime.fromtimestamp(stat.st_mtime).strftime('%a %b %d %H:%M:%S %Y')
                patches.append((name, size, date))
            patches.sort(key=lambda x: x[0])
            return patches
        else:
            remote_dir = self._get_remote_dir()
            smb_subcmd = f"ls {remote_dir}\\{repo_name}\\*.patch"
            result = self._smb_cmd(smb_subcmd)
            if result.returncode != 0:
                return []
            return self._parse_ls_output(result.stdout)

    def _upload_patch(self, repo_name, local_patch, local_msg, filename, msg_filename):
        """Upload a patch and its message file to the share."""
        backend, _ = self._detect_backend()

        if backend == 'mount':
            dest_dir = self._get_share_path(repo_name)
            os.makedirs(dest_dir, exist_ok=True)
            shutil.copy2(local_patch, os.path.join(dest_dir, filename))
            shutil.copy2(local_msg, os.path.join(dest_dir, msg_filename))
        else:
            remote_dir = self._get_remote_dir()
            smb_subcmd = (
                f"mkdir {remote_dir}; "
                f"mkdir {remote_dir}\\{repo_name}; "
                f"cd {remote_dir}\\{repo_name}; "
                f"put {local_patch} {filename}; "
                f"put {local_msg} {msg_filename}"
            )
            result = self._smb_cmd(smb_subcmd)

            stderr_lines = result.stderr.strip().split('\n') if result.stderr else []
            real_errors = [
                line for line in stderr_lines
                if line.strip() and 'NT_STATUS_OBJECT_NAME_COLLISION' not in line
            ]

            if result.returncode != 0 and real_errors:
                print("Error uploading patch to SMB share:")
                print('\n'.join(real_errors))
                sys.exit(1)

    def _download_patch(self, repo_name, patch_name, dest_path):
        """Download a single patch file from the share."""
        backend, _ = self._detect_backend()

        if backend == 'mount':
            src = self._get_share_path(repo_name, patch_name)
            shutil.copy2(src, dest_path)
        else:
            remote_dir = self._get_remote_dir()
            smb_subcmd = (
                f"cd {remote_dir}\\{repo_name}; "
                f"get {patch_name} {dest_path}"
            )
            result = self._smb_cmd(smb_subcmd)
            if result.returncode != 0:
                print("Error downloading patch:")
                print(result.stderr)
                raise RuntimeError("Download failed")

    def _delete_patches(self, repo_name, patch_names):
        """Delete patch and message files from the share."""
        backend, _ = self._detect_backend()

        if backend == 'mount':
            for name in patch_names:
                patch_path = self._get_share_path(repo_name, name)
                if os.path.exists(patch_path):
                    os.remove(patch_path)
                msg_name = name.rsplit('.patch', 1)[0] + '.msg'
                msg_path = self._get_share_path(repo_name, msg_name)
                if os.path.exists(msg_path):
                    os.remove(msg_path)
        else:
            remote_dir = self._get_remote_dir()
            delete_cmds = []
            for name in patch_names:
                delete_cmds.append(f"del {name}")
                msg_name = name.rsplit('.patch', 1)[0] + '.msg'
                delete_cmds.append(f"del {msg_name}")

            smb_subcmd = f"cd {remote_dir}\\{repo_name}; {'; '.join(delete_cmds)}"
            result = self._smb_cmd(smb_subcmd)

            stderr_lines = result.stderr.strip().split('\n') if result.stderr else []
            real_errors = [
                line for line in stderr_lines
                if line.strip()
                and 'NT_STATUS_OBJECT_NAME_NOT_FOUND' not in line
                and 'NT_STATUS_NO_SUCH_FILE' not in line
            ]

            if result.returncode != 0 and real_errors:
                print("Error cleaning patches:")
                print('\n'.join(real_errors))
                raise RuntimeError("Delete failed")

    def _get_stash_message(self, stash_ref):
        """Get the message for a stash ref from git stash list."""
        result = self._run_command('git stash list', cwd=self._get_cwd(), capture=True)
        if result.returncode != 0 or not result.stdout.strip():
            return ''
        # stash_ref is like "stash@{0}", look for matching line
        for line in result.stdout.strip().split('\n'):
            if line.startswith(stash_ref):
                # Format: "stash@{0}: On branch: message"
                parts = line.split(':', 2)
                if len(parts) >= 3:
                    return parts[2].strip()
                return ''
        return ''

    def _get_stash_hash(self, stash_ref):
        """Get the short commit hash for a stash ref."""
        result = self._run_command(
            f'git rev-parse --short=8 "{stash_ref}"',
            cwd=self._get_cwd(), capture=True
        )
        if result.returncode != 0 or not result.stdout.strip():
            return ''
        return result.stdout.strip()

    def _inject_stash_from_patch(self, patch_path, stash_msg):
        """Inject a stash entry directly from a patch file without touching the working directory."""
        cwd = self._get_cwd()

        # Get HEAD commit hash and tree
        head_result = self._run_command('git rev-parse HEAD', cwd=cwd, capture=True)
        if head_result.returncode != 0:
            print("Error: Could not resolve HEAD.")
            return False
        head = head_result.stdout.strip()

        head_tree_result = self._run_command('git rev-parse HEAD^{tree}', cwd=cwd, capture=True)
        if head_tree_result.returncode != 0:
            print("Error: Could not resolve HEAD tree.")
            return False
        head_tree = head_tree_result.stdout.strip()

        # Get branch name
        branch_result = self._run_command('git branch --show-current', cwd=cwd, capture=True)
        branch = branch_result.stdout.strip() if branch_result.returncode == 0 and branch_result.stdout.strip() else 'detached'

        # Get short HEAD description
        head_short_result = self._run_command("git log -1 --format='%h %s' HEAD", cwd=cwd, capture=True)
        head_short = head_short_result.stdout.strip().strip("'") if head_short_result.returncode == 0 else head[:7]

        # Create I commit (index state — identical to HEAD tree since we only modify W)
        i_msg = f"index on {branch}: {head_short}"
        i_result = self._run_command(
            f'git commit-tree {head_tree} -p {head} -m "{i_msg}"',
            cwd=cwd, capture=True
        )
        if i_result.returncode != 0:
            print("Error creating index commit:")
            print(i_result.stderr)
            return False
        i_commit = i_result.stdout.strip()

        # Create temporary index file
        tmp_index = tempfile.mktemp(prefix='sendstash_idx_')
        tmp_env = dict(os.environ, GIT_INDEX_FILE=tmp_index)

        try:
            # Populate temp index with HEAD's tree
            r = self._run_command('git read-tree HEAD', cwd=cwd, capture=True, env=tmp_env)
            if r.returncode != 0:
                print("Error populating temp index:")
                print(r.stderr)
                return False

            # Apply patch to temp index
            r = self._run_command(f'git apply --cached {patch_path}', cwd=cwd, capture=True, env=tmp_env)
            if r.returncode != 0:
                print("Error applying patch to index:")
                print(r.stderr)
                return False

            # Write tree from temp index
            r = self._run_command('git write-tree', cwd=cwd, capture=True, env=tmp_env)
            if r.returncode != 0:
                print("Error writing tree:")
                print(r.stderr)
                return False
            w_tree = r.stdout.strip()
        finally:
            if os.path.exists(tmp_index):
                os.unlink(tmp_index)

        # Create W commit (working tree state)
        w_msg = f"On {branch}: {stash_msg}" if stash_msg else f"On {branch}: WIP"
        w_result = self._run_command(
            f'git commit-tree {w_tree} -p {head} -p {i_commit} -m "{w_msg}"',
            cwd=cwd, capture=True
        )
        if w_result.returncode != 0:
            print("Error creating working-tree commit:")
            print(w_result.stderr)
            return False
        w_commit = w_result.stdout.strip()

        # Store as stash entry
        store_result = self._run_command(
            f'git stash store -m "{w_msg}" {w_commit}',
            cwd=cwd, capture=True
        )
        if store_result.returncode != 0:
            print("Error storing stash:")
            print(store_result.stderr)
            return False

        return True

    def _get_remote_hashes(self):
        """Get the set of stash hashes already present on the SMB share."""
        repo_name = self._get_repo_name()
        patches = self._list_patches_raw(repo_name)
        hashes = set()
        for name, _, _ in patches:
            # Extract 8-char hex hash from filename: branch_name_HASH_timestamp.patch
            match = re.search(r'_([0-9a-f]{8})_\d{4}-\d{2}-\d{2}_', name)
            if match:
                hashes.add(match.group(1))
        return hashes

    def _list_stash_refs(self):
        """Returns a list of (ref, message) for all stash entries."""
        result = self._run_command('git stash list', cwd=self._get_cwd(), capture=True)
        if result.returncode != 0 or not result.stdout.strip():
            return []
        entries = []
        for line in result.stdout.strip().split('\n'):
            parts = line.split(':', 2)
            ref = parts[0].strip()
            message = parts[2].strip() if len(parts) >= 3 else ''
            entries.append((ref, message))
        return entries

    def push_all(self, message=None):
        """Push all stash entries to the SMB share."""
        entries = self._list_stash_refs()
        if not entries:
            print("No stashes found.")
            return

        # Get existing patches on SMB to avoid duplicates
        remote_hashes = self._get_remote_hashes()

        for ref, _ in entries:
            stash_hash = self._get_stash_hash(ref)
            if stash_hash and stash_hash in remote_hashes:
                print(f"\n--- Skipping {ref} (already pushed: {stash_hash}) ---")
                continue
            print(f"\n--- Pushing {ref} ---")
            self.push(message=message, stash_ref=ref)

    def push(self, message=None, stash_ref='stash@{0}'):
        """Push a stash patch to the SMB share."""
        repo_name = self._get_repo_name()
        branch = self._get_branch_name()
        remote_dir = self._get_remote_dir()

        # Generate the patch from stash
        result = self._run_command(f'git stash show -p "{stash_ref}"', cwd=self._get_cwd(), capture=True)
        if result.returncode != 0:
            print(f"Error: Could not generate patch from {stash_ref}")
            print(result.stderr)
            sys.exit(1)

        patch_content = result.stdout
        if not patch_content.strip():
            print(f"Error: Empty patch from {stash_ref}")
            sys.exit(1)

        # Get stash name from git for the filename
        stash_name = self._get_stash_message(stash_ref)

        # Resolve .msg content: explicit flag > git stash name > empty
        if message is None:
            message = stash_name

        # Generate filename
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        sanitized_branch = self._sanitize_name(branch)
        stash_hash = self._get_stash_hash(stash_ref)
        # Include stash name in filename if available: branch_stashname_hash_timestamp
        stash_label = self._sanitize_for_filename(stash_name) if stash_name else ''
        if stash_label and stash_hash:
            base_name = f"{sanitized_branch}_{stash_label}_{stash_hash}_{timestamp}"
        elif stash_label:
            base_name = f"{sanitized_branch}_{stash_label}_{timestamp}"
        elif stash_hash:
            base_name = f"{sanitized_branch}_{stash_hash}_{timestamp}"
        else:
            base_name = f"{sanitized_branch}_{timestamp}"
        filename = f"{base_name}.patch"
        msg_filename = f"{base_name}.msg"

        # Write patch to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.patch', delete=False) as f:
            f.write(patch_content)
            temp_patch_path = f.name

        # Write message to temp file (with stash_name header)
        with tempfile.NamedTemporaryFile(mode='w', suffix='.msg', delete=False) as f:
            f.write(f"stash_name: {stash_name}\n---\n{message}")
            temp_msg_path = f.name

        try:
            self._upload_patch(repo_name, temp_patch_path, temp_msg_path, filename, msg_filename)
            print(f"Pushed stash patch to: {remote_dir}/{repo_name}/{filename}")
            if message:
                print(f"Message: {message}")
        finally:
            os.unlink(temp_patch_path)
            os.unlink(temp_msg_path)

    def _parse_msg_file(self, content):
        """Parse .msg file content. Returns (stash_name, message).

        New format:
            stash_name: WIP on login feature
            ---
            User's custom message here

        Old format (backward compat): entire content is the message, stash_name is empty.
        """
        if '---' in content:
            header, _, body = content.partition('---')
            stash_name = ''
            for line in header.strip().split('\n'):
                if line.startswith('stash_name:'):
                    stash_name = line[len('stash_name:'):].strip()
                    break
            return (stash_name, body.strip())
        return ('', content.strip())

    def _format_msg_display(self, stash_name, message):
        """Format stash_name and message for display."""
        if stash_name and message and stash_name != message:
            return f'{stash_name} \u2014 {message}'
        if stash_name:
            return stash_name
        return message

    def _fetch_messages(self, repo_name, patches):
        """Batch-download .msg files for a list of patches. Returns dict of patch_name -> (stash_name, message)."""
        backend, _ = self._detect_backend()
        messages = {}

        if backend == 'mount':
            for name, _, _ in patches:
                base = name.rsplit('.patch', 1)[0]
                msg_path = self._get_share_path(repo_name, f"{base}.msg")
                if os.path.exists(msg_path):
                    with open(msg_path, 'r') as f:
                        messages[name] = self._parse_msg_file(f.read())
        else:
            remote_dir = self._get_remote_dir()
            with tempfile.TemporaryDirectory() as tmpdir:
                smb_subcmd = (
                    f"cd {remote_dir}\\{repo_name}; "
                    f"prompt OFF; "
                    f"lcd {tmpdir}; "
                    f"mget *.msg"
                )
                self._smb_cmd(smb_subcmd)

                for name, _, _ in patches:
                    base = name.rsplit('.patch', 1)[0]
                    msg_path = os.path.join(tmpdir, f"{base}.msg")
                    if os.path.exists(msg_path):
                        with open(msg_path, 'r') as f:
                            messages[name] = self._parse_msg_file(f.read())

        return messages

    def list_patches(self):
        """List available patches on the SMB share for the current repo."""
        repo_name = self._get_repo_name()

        patches = self._list_patches_raw(repo_name)

        if not patches:
            print(f"No patches found for repo '{repo_name}'.")
            return []

        # Fetch messages for all patches in one smbclient call
        messages = self._fetch_messages(repo_name, patches)

        print(f"Patches for '{repo_name}':")
        for i, (name, size, date) in enumerate(patches, 1):
            stash_name, msg = messages.get(name, ('', ''))
            display = self._format_msg_display(stash_name, msg)
            msg_display = f'  "{display}"' if display else ''
            print(f"  {i}. {name}  ({size} bytes, {date}){msg_display}")

        return patches

    def _parse_ls_output(self, output):
        """Parse smbclient ls output into list of (filename, size, date_string)."""
        patches = []
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line or not line.endswith('.patch'):
                # Try to parse lines that contain .patch
                pass

            # smbclient ls format: "  filename    A    size  date"
            # Match lines containing .patch files
            match = re.match(
                r'\s*(\S+\.patch)\s+[A-Za-z]*\s+(\d+)\s+(.*)',
                line
            )
            if match:
                name = match.group(1)
                size = match.group(2)
                date = match.group(3).strip()
                patches.append((name, size, date))

        # Sort by filename (which contains timestamp) so newest is last
        patches.sort(key=lambda x: x[0])
        return patches

    def pull(self, latest=True, pick=False, number=None, name=None, apply_to_workdir=False):
        """Pull a stash patch from the SMB share and restore it as a stash entry (or apply directly with --apply)."""
        repo_name = self._get_repo_name()

        patches = self._list_patches_raw(repo_name)
        if not patches:
            print(f"No patches found for repo '{repo_name}'.")
            return

        # Fetch messages (needed for display and stash-restore)
        messages = self._fetch_messages(repo_name, patches)

        if number is not None:
            if number < 1 or number > len(patches):
                print(f"Invalid patch number: {number}. Must be between 1 and {len(patches)}.")
                return
            selected = patches[number - 1]
            stash_name, msg = messages.get(selected[0], ('', ''))
            display = self._format_msg_display(stash_name, msg)
            msg_display = f'  "{display}"' if display else ''
            print(f"Selected patch {number}: {selected[0]}{msg_display}")
        elif name is not None:
            matches = [(i, p) for i, p in enumerate(patches, 1) if name.lower() in p[0].lower()]
            if not matches:
                print(f"No patches matching '{name}'.")
                return
            if len(matches) > 1:
                print(f"Multiple patches match '{name}':")
                for i, (num, (pname, size, date)) in enumerate(matches):
                    stash_name, msg = messages.get(pname, ('', ''))
                    display = self._format_msg_display(stash_name, msg)
                    msg_display = f'  "{display}"' if display else ''
                    print(f"  {num}. {pname}  ({size} bytes, {date}){msg_display}")
                print("Please be more specific.")
                return
            selected = matches[0][1]
            stash_name, msg = messages.get(selected[0], ('', ''))
            display = self._format_msg_display(stash_name, msg)
            msg_display = f'  "{display}"' if display else ''
            print(f"Selected patch: {selected[0]}{msg_display}")
        elif pick:
            # Show list and let user choose
            print(f"Available patches for '{repo_name}':")
            for i, (pname, size, date) in enumerate(patches, 1):
                stash_name, msg = messages.get(pname, ('', ''))
                display = self._format_msg_display(stash_name, msg)
                msg_display = f'  "{display}"' if display else ''
                print(f"  {i}. {pname}  ({size} bytes, {date}){msg_display}")

            try:
                choice = int(input("\nSelect patch number: "))
                if choice < 1 or choice > len(patches):
                    print("Invalid selection.")
                    return
                selected = patches[choice - 1]
            except (ValueError, EOFError):
                print("Invalid selection.")
                return
        else:
            # Default: latest (last in sorted list)
            selected = patches[-1]

        patch_name = selected[0]
        selected_stash_name, selected_msg = messages.get(patch_name, ('', ''))

        print(f"Downloading: {patch_name}")

        # Download patch to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.patch', delete=False) as f:
            temp_path = f.name

        try:
            try:
                self._download_patch(repo_name, patch_name, temp_path)
            except RuntimeError:
                return

            if apply_to_workdir:
                # Apply directly to working directory
                apply_result = self._run_command(f'git apply {temp_path}', cwd=self._get_cwd(), capture=True)
                if apply_result.returncode != 0:
                    print("Error applying patch:")
                    print(apply_result.stderr)
                    print("\nPatch saved at:", temp_path)
                    return
                print(f"Successfully applied patch: {patch_name}")
            else:
                # Stash-restore mode: inject stash directly without touching working directory
                stash_label = selected_stash_name or selected_msg
                if not self._inject_stash_from_patch(temp_path, stash_label):
                    print("\nPatch saved at:", temp_path)
                    return

                print(f"Restored stash: {stash_label or patch_name}")
                # Show top stash entry
                list_result = self._run_command('git stash list -1', cwd=self._get_cwd(), capture=True)
                if list_result.returncode == 0 and list_result.stdout.strip():
                    print(list_result.stdout.strip())
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def pull_all(self):
        """Pull all patches from the SMB share and inject each as a stash entry."""
        repo_name = self._get_repo_name()

        patches = self._list_patches_raw(repo_name)
        if not patches:
            print(f"No patches found for repo '{repo_name}'.")
            return

        messages = self._fetch_messages(repo_name, patches)

        success_count = 0
        total = len(patches)

        for patch_name, size, date in patches:
            print(f"\n--- Pulling {patch_name} ---")

            stash_name, msg = messages.get(patch_name, ('', ''))
            stash_label = stash_name or msg or ''

            with tempfile.NamedTemporaryFile(mode='w', suffix='.patch', delete=False) as f:
                temp_path = f.name

            try:
                try:
                    self._download_patch(repo_name, patch_name, temp_path)
                except RuntimeError:
                    print(f"Failed to download {patch_name}")
                    continue

                if self._inject_stash_from_patch(temp_path, stash_label):
                    print(f"Restored stash: {stash_label or patch_name}")
                    success_count += 1
                else:
                    print(f"Failed to inject stash from {patch_name}")
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)

        print(f"\nPulled {success_count} of {total} patch(es) as stash entries")

    def clean(self, all_patches=False, older_than=None, pick=False):
        """Remove old patches from the SMB share for the current repo."""
        repo_name = self._get_repo_name()

        patches = self._list_patches_raw(repo_name)
        if not patches:
            print(f"No patches found for repo '{repo_name}'.")
            return

        to_delete = []

        if pick:
            messages = self._fetch_messages(repo_name, patches)

            print(f"Available patches for '{repo_name}':")
            for i, (name, size, date) in enumerate(patches, 1):
                stash_name, msg = messages.get(name, ('', ''))
                display = self._format_msg_display(stash_name, msg)
                msg_display = f'  "{display}"' if display else ''
                print(f"  {i}. {name}  ({size} bytes, {date}){msg_display}")

            try:
                raw = input("\nSelect patch numbers to delete (comma-separated, e.g. 1,3,5): ")
                choices = [int(x.strip()) for x in raw.split(',')]
            except (ValueError, EOFError):
                print("Invalid input.")
                return

            for c in choices:
                if c < 1 or c > len(patches):
                    print(f"Invalid selection: {c} (must be 1-{len(patches)})")
                    return

            to_delete = [patches[c - 1][0] for c in choices]
        elif all_patches:
            to_delete = [p[0] for p in patches]
        elif older_than is not None:
            cutoff = datetime.now() - timedelta(days=older_than)
            for name, size, date in patches:
                # Extract timestamp from filename: branch_YYYY-MM-DD_HH-MM-SS.patch
                ts_match = re.search(r'(\d{4}-\d{2}-\d{2}_\d{2}-\d{2}-\d{2})\.patch$', name)
                if ts_match:
                    try:
                        patch_time = datetime.strptime(ts_match.group(1), '%Y-%m-%d_%H-%M-%S')
                        if patch_time < cutoff:
                            to_delete.append(name)
                    except ValueError:
                        continue

        if not to_delete:
            print("No patches to clean.")
            return

        try:
            self._delete_patches(repo_name, to_delete)
        except RuntimeError:
            return

        print(f"Cleaned {len(to_delete)} patch(es) from '{repo_name}':")
        for name in to_delete:
            print(f"  - {name}")


def main():
    # Pre-parse --config so we can load projects before building the full parser
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument('--config')
    pre_parser.add_argument('--sync-config', action='store_true')
    pre_parser.add_argument('--open', action='store_true')
    pre_args, _ = pre_parser.parse_known_args()

    stash = SendStash(config_path=pre_args.config)

    if pre_args.open:
        stash.open_folder()
        return

    if pre_args.sync_config:
        stash.sync_config()

    project_choices = stash.get_project_choices() or None

    parser = argparse.ArgumentParser(
        description="Sync git stash patches via SMB share."
    )
    parser.add_argument('--config', help="Path to config.yaml")
    parser.add_argument('--sync-config', action='store_true', help="Sync the configuration from its source before running the command")
    parser.add_argument('--open', action='store_true', help="Open the SendStash directory in file explorer")

    subparsers = parser.add_subparsers(dest='command', help="Available commands")

    # Shared parent parser for --project
    project_parser = argparse.ArgumentParser(add_help=False)
    project_parser.add_argument(
        '--project', '-p', choices=project_choices,
        help="Use a configured project instead of the current directory"
    )

    # push
    push_parser = subparsers.add_parser('push', parents=[project_parser], help="Push a stash patch to the SMB share")
    push_parser.add_argument('--message', '-m', help="Optional message/description for the patch")
    push_stash_group = push_parser.add_mutually_exclusive_group()
    push_stash_group.add_argument('--stash', default='stash@{0}', help="Stash reference (default: stash@{0})")
    push_stash_group.add_argument('--stash-all', action='store_true', help="Push all stash entries")

    # pull
    pull_parser = subparsers.add_parser('pull', parents=[project_parser], help="Pull and apply a stash patch from the SMB share")
    pull_group = pull_parser.add_mutually_exclusive_group()
    pull_group.add_argument('--latest', action='store_true', default=True, help="Pull the most recent patch (default)")
    pull_group.add_argument('--pick', action='store_true', help="Interactively choose which patch to apply")
    pull_group.add_argument('--number', '-n', type=int, help="Pull patch by its list number")
    pull_group.add_argument('--name', help="Pull patch by name substring match")
    pull_group.add_argument('--all', action='store_true', help="Pull all patches as stash entries")
    pull_parser.add_argument('--apply', action='store_true',
        help="Apply patch to working directory instead of restoring as stash entry")

    # list
    subparsers.add_parser('list', parents=[project_parser], help="List available patches on the SMB share")

    # clean
    clean_parser = subparsers.add_parser('clean', parents=[project_parser], help="Remove old patches from the SMB share")
    clean_group = clean_parser.add_mutually_exclusive_group(required=True)
    clean_group.add_argument('--all', action='store_true', help="Remove all patches for the current repo")
    clean_group.add_argument('--older-than', type=int, metavar='DAYS', help="Remove patches older than N days")
    clean_group.add_argument('--pick', action='store_true', help="Interactively choose patches to delete")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    if args.project:
        stash.set_project(args.project)

    if args.command == 'push':
        if args.stash_all:
            stash.push_all(message=args.message)
        else:
            stash.push(message=args.message, stash_ref=args.stash)
    elif args.command == 'pull':
        if args.all:
            stash.pull_all()
        else:
            stash.pull(latest=not args.pick, pick=args.pick, number=args.number, name=args.name, apply_to_workdir=args.apply)
    elif args.command == 'list':
        stash.list_patches()
    elif args.command == 'clean':
        stash.clean(all_patches=args.all, older_than=args.older_than, pick=args.pick)


if __name__ == '__main__':
    main()
