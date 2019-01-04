SNMP Trapを受け取り、TrapのOIDに基づいてログ書き込み/外部スクリプト起動/Trap転送を行う。

## 使い方
```
traphandle -config config.toml
```

ポート162/udpで待ち受けるにはroot権限が必須。

## 設定ファイル

設定はTOML形式で記述する

```
[source]
version = "2c"
community = "public"
address = "0.0.0.0:162"

# Log all traps to logfile
[[pipe]]
  oid = "."
  [pipe.log]
  logfile = "/path/to/logfile"

# Drop OIDs that starts with ".1.3.6.1.6.3.1.1.5.4"
[[pipe]]
  oid = ".1.3.6.1.6.3.1.1.5.4"
  drop = true

# Drop OIDs that starts with ".1.3.6.1.6.3.1.1.5.3" and execute a command
[[pipe]]
  oid = ".1.3.6.1.6.3.1.1.5.3"
  drop = true
  [pipe.cmd]
  command = "/path/to/command"

# Forward all traps except ".1.3.6.1.6.3.1.1.5.4" and ".1.3.6.1.6.3.1.1.5.3"
[[pipe]]
  # "." matches all OIDs
  oid = "."
  [pipe.fwd]
  # Forward handle only support SNMP Version 1
  version = "1"
  community = "public"
  address = "10.10.10.10:161"
```
