# DNS Apps

[Documentation](README.md) · [Quick start](../README.md#quick-start)

Any app from the Technitium App Store, or any app package URL, can be installed. [Block ads and trackers](recipes.md#block-ads-and-trackers) shows a complete app config.

```yaml
apps:
  - name: "NO DATA"
    url: "https://download.technitium.com/dns/apps/NoDataApp-v6.zip"
```

- `config` is converted to JSON and passed to the app, so every field the app accepts can be used. YAML merge keys (`<<`) are resolved; duplicate keys (including a second `<<` in one mapping: merge several with `<<: [*a, *b]`) and aliases that contain themselves are errors. Give the **complete** document: missing keys can cause rejection or a failure after a cold start. Start from the app's `dnsApp.config` in the [Technitium source](https://github.com/TechnitiumSoftware/DnsServer/tree/master/Apps).
- Leave `config` out to keep the app's current config. Apps used only through APP records (NO DATA, Auto PTR, Wild IP and others) need none.
- Config is written only when it differs from the stored config, compared as JSON; comments in the stored config are ignored, as the apps ignore them. Numbers keep every digit in any YAML spelling, so 64-bit integers and long decimals are passed exactly.
- `url` is needed only to install the app. An installed app is not downloaded again; app upgrades and uninstalls are not performed.
- Package URLs and the server versions they need are in the App Store catalogue, [`Apps/apps2.json`](https://github.com/TechnitiumSoftware/DnsServer/blob/master/Apps/apps2.json). For v15.6: Advanced Blocking `AdvancedBlockingApp-v11.2.1.zip`, Advanced Forwarding `AdvancedForwardingApp-v5.2.zip`.
- Apps that answer through APP records (Split Horizon, Geo, Failover, Weighted Round Robin and others) are configured with `type: APP` records. Apps are installed before APP records and every other record type except FWD.

Advanced Blocking 11.2.1 needs an explicit `localEndPointGroupMap: {}` when
client selection uses only network groups. Include `blockingAnswerTtl` and
`blockListUrlUpdateIntervalMinutes` from its current schema too. Use the complete
[example](../examples/config.yaml) or [recipe](recipes.md#block-ads-and-trackers),
and verify a blocked query's app report after restarting the server. A successful
config write alone does not establish that filtering initializes correctly.
