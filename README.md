# UniFi IPv6 Dynamic DNS Updater

A script to update your DNS provider with the current IPv6 address of your UniFi device.
This tool addresses the common issue where internet service providers (ISPs) may periodically change the IPv6 prefix
assigned to your home network, causing DNS records to become stale.

By automatically detecting the current WAN IPv6 address from your UniFi gateway and updating a dynamic DNS record,
this script ensures your services remain accessible.

_NOTE: at this stage, UniFi does not provide direct support for Dynamic DNS with IPv6._

## Supported Providers

Currently, this script supports the following DNS providers:

* Hurricane Electric (HE)

* Cloudflare

## Tested Devices

The code has been specifically tested with the UniFi Cloud Gateway Ultra (UDRULT). While it may work with other UniFi
OS-based consoles, this is the only device for which functionality is confirmed. Please open an issue / pull request
to add more devices to the list.

## Getting Started

To run this script, you need to set up the appropriate environment variables based on your chosen DNS provider.

1. **UniFi Configuration**

   All configurations require the following UniFi-related environment variables:

| Variable             | Description                                                                                                             |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------|
| UNIFI_CONTROLLER_URL | The URL of your UniFi controller (e.g., https://192.168.0.1).<br/> If not provided, it defaults to https://192.168.0.1. |
| UNIFI_SITE_NAME      | The name of your UniFi site (e.g., default). If not provided, it defaults to default.                                   |
| UNIFI_API_USERNAME   | Your UniFi OS username with read-only API access.                                                                       |
| UNIFI_API_PASSWORD   | Your UniFi OS password.                                                                                                 |

2. **Provider-Specific Configuration**

   Set the DNS_PROVIDER environment variable to either HE or Cloudflare, and then configure the required variables
   for your provider.

### Hurricane Electric (HE)

| Variable    | Description                                              |
|:------------|:---------------------------------------------------------|
| HE_HOSTNAME | The hostname of your DNS record (e.g., dyn.example.com). |
| HE_PASSWORD | The password for the DNS update.                         |

Example:

```bash
export DNS_PROVIDER=HE
export HE_HOSTNAME="dyn.example.com"
export HE_PASSWORD="your-he-password"
export UNIFI_API_USERNAME="your-unifi-username"
export UNIFI_API_PASSWORD="your-unifi-password"
```

### Cloudflare

| Variable               | Description                                                              |
|:-----------------------|:-------------------------------------------------------------------------|
| CLOUDFLARE_API_TOKEN   | A Cloudflare API token with Zone > DNS > Edit permissions for your zone. |
| CLOUDFLARE_ZONE_ID     | The ID of the DNS zone you are managing.                                 |
| CLOUDFLARE_RECORD_NAME | The name of the AAAA record to update (e.g., ddns.example.com).          |

Example:

```bash
export DNS_PROVIDER=Cloudflare
export CLOUDFLARE_API_TOKEN="your-cloudflare-api-token"
export CLOUDFLARE_ZONE_ID="your-cloudflare-zone-id"
export CLOUDFLARE_RECORD_NAME="ddns.example.com"
export UNIFI_API_USERNAME="your-unifi-username"
export UNIFI_API_PASSWORD="your-unifi-password"
```

## Contributing

If you wish to contribute or suggest changes, please open an issue or pull request.
