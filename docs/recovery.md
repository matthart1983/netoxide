# If you lock yourself out

A firewall change can cut the connection you made it over. Netoxide is built so that this undoes itself, and this page covers the cases where it did not.

## Before it happens

- **Commit with a timer when the change could cut you off.** `ox commit <candidate> --confirm 5m` goes back by itself unless you run `ox confirm` in time. The web UI and the terminal UI always offer a timer.
- **Keep a way in that does not cross the firewall.** A monitor and keyboard, a serial console, or the hypervisor's console for a VM. Do not rely on SSH through the box as your only way to the box.
- **Use `--lockdown` only with console access.** It drops inbound traffic on a box with no config, which includes SSH.

## You committed with a timer

Wait. When the window lapses the box applies the previous commit, and your connection works again. The daemon also reverts an unconfirmed commit if it restarts or the machine reboots, so pulling the power is safe.

## You committed without a timer, or confirmed too early

You need the console. Log in on the box and pick one.

**Go back one commit.** This is the normal way:

```sh
ox rollback 1 --reason "locked out"
ox status
```

`ox history` lists earlier commits if one step is not far enough; `ox rollback 3` goes back three.

**The daemon is not answering.** Look at why, then restart it. On start it applies the running commit again:

```sh
systemctl status oxd
journalctl -u oxd -n 50
sudo systemctl restart oxd
```

**You need traffic flowing right now.** Stop the daemon and remove its rules. The box then filters nothing, so do this only for as long as it takes to fix the config:

```sh
sudo systemctl stop oxd
sudo nft delete table inet netoxide
```

Stopping the daemon by itself does not remove the rules: the kernel keeps the last ruleset that was loaded. Starting the daemon again loads the running commit.

## The web UI or `ox --remote` cannot reach the box, but traffic is fine

- The HTTPS listener needs a rule that allows its port from where you are. On the box, `ox explain --src <your address> --dst <the box's address> --proto tcp --dport 8443 --in <port>` says which rule decided.
- If the box's certificate changed, `ox --remote` refuses to send your token and says so. Compare the fingerprint with `ox status` on the box and run `ox remote add` again.
- A token that expired or was revoked gets "unknown, expired or revoked". Make a new one on the box with `ox token create`.

## You lost the admin token

Tokens are for the HTTPS listener only. On the box, anyone who can open the daemon's socket is an administrator, so `sudo ox token create <name> --role admin` makes a new one.

## Nothing above worked

The state is in `/var/lib/netoxide`. Each commit's config is a TOML file under `commits/`. Copy the one you want somewhere safe, then reinstall by [dist/README.md](../dist/README.md) and load it with `ox candidate save` and `ox commit`.
