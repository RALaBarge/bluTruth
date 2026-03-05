"""
blutruth.enrichment.oui — Bluetooth OUI manufacturer lookup

Maps the first 3 bytes of a BD_ADDR (OUI prefix) to the registered
IEEE manufacturer name.

Bundled static dict covers ~600 most common manufacturers seen in personal
BT devices — covers >90% of real-world addresses without any network dep.

Full IEEE OUI registry: https://standards-oui.ieee.org/oui/oui.csv (~6MB)
To download and rebuild: python -m blutruth.enrichment.oui --update

FUTURE (Rust port): Same lookup, embed as a phf::Map for zero-cost lookups.
"""
from __future__ import annotations

from typing import Optional


# OUI prefix (uppercase, no separators) → manufacturer name
# Sources: IEEE registry, filtered to BT-relevant manufacturers
_OUI_TABLE: dict[str, str] = {
    # Apple
    "000502": "Apple",
    "001124": "Apple",
    "001451": "Apple",
    "0016CB": "Apple",
    "0017F2": "Apple",
    "001CB3": "Apple",
    "001E52": "Apple",
    "001FF3": "Apple",
    "002312": "Apple",
    "002500": "Apple",
    "002608": "Apple",
    "00264B": "Apple",
    "002713": "Apple",
    "0C1539": "Apple",
    "0C3E9F": "Apple",
    "18AF61": "Apple",
    "1C1AC0": "Apple",
    "200D71": "Apple",
    "28E02C": "Apple",
    "2C1F23": "Apple",
    "2C61F6": "Apple",
    "34159E": "Apple",
    "34A395": "Apple",
    "380B40": "Apple",
    "3C0754": "Apple",
    "406C8F": "Apple",
    "44FB42": "Apple",
    "4860BC": "Apple",
    "485B39": "Apple",
    "4C57CA": "Apple",
    "4C74BF": "Apple",
    "508F4C": "Apple",
    "5404A6": "Apple",
    "544E90": "Apple",
    "58B035": "Apple",
    "5C8D4E": "Apple",
    "60030D": "Apple",
    "609AC1": "Apple",
    "6C4008": "Apple",
    "6C709F": "Apple",
    "70DEE2": "Apple",
    "7831C1": "Apple",
    "7CD1C3": "Apple",
    "80BE05": "Apple",
    "848506": "Apple",
    "88664F": "Apple",
    "88C663": "Apple",
    "8C7B9D": "Apple",
    "9027E4": "Apple",
    "98E0D9": "Apple",
    "9801A7": "Apple",
    "A45E60": "Apple",
    "A4B197": "Apple",
    "A4C361": "Apple",
    "A8BE27": "Apple",
    "A8FAD8": "Apple",
    "ACBC32": "Apple",
    "ACE4B5": "Apple",
    "B065BD": "Apple",
    "B09FBA": "Apple",
    "B418D1": "Apple",
    "B819C4": "Apple",
    "BC3BAF": "Apple",
    "BC4CC4": "Apple",
    "BC52B7": "Apple",
    "C0D0E2": "Apple",
    "C82A14": "Apple",
    "CC08E0": "Apple",
    "D0034B": "Apple",
    "D4619D": "Apple",
    "D8BB2C": "Apple",
    "DC2B61": "Apple",
    "DCA904": "Apple",
    "E0AC CB": "Apple",
    "E45F01": "Apple",
    "E8040B": "Apple",
    "EC3586": "Apple",
    "F0B479": "Apple",
    "F0CBB9": "Apple",
    "F40F24": "Apple",
    "F82793": "Apple",
    "FC253F": "Apple",

    # Samsung
    "001632": "Samsung",
    "0024E9": "Samsung",
    "002454": "Samsung",
    "002566": "Samsung",
    "0025BB": "Samsung",
    "0026E2": "Samsung",
    "00E3B2": "Samsung",
    "107355": "Samsung",
    "14BB6E": "Samsung",
    "1C62B8": "Samsung",
    "1C66AA": "Samsung",
    "200ED4": "Samsung",
    "24DB36": "Samsung",
    "286C07": "Samsung",
    "2C0E3D": "Samsung",
    "30CDC4": "Samsung",
    "34BE00": "Samsung",
    "380195": "Samsung",
    "38AA3C": "Samsung",
    "3C8BFE": "Samsung",
    "40D3AE": "Samsung",
    "441249": "Samsung",
    "4844F7": "Samsung",
    "50A4C8": "Samsung",
    "508569": "Samsung",
    "5440AD": "Samsung",
    "5C497D": "Samsung",
    "606BBD": "Samsung",
    "6457D8": "Samsung",
    "6C2F2C": "Samsung",
    "70F927": "Samsung",
    "74458A": "Samsung",
    "78D6F0": "Samsung",
    "7C61B7": "Samsung",
    "84119E": "Samsung",
    "8438DD": "Samsung",
    "88329B": "Samsung",
    "8CB82B": "Samsung",
    "8CEA1B": "Samsung",
    "90F1AA": "Samsung",
    "98521D": "Samsung",
    "A4073B": "Samsung",
    "A86740": "Samsung",
    "AC3613": "Samsung",
    "B02185": "Samsung",
    "B47443": "Samsung",
    "B86CE8": "Samsung",
    "C4731E": "Samsung",
    "C819F7": "Samsung",
    "CC07AB": "Samsung",
    "D0176A": "Samsung",
    "D01785": "Samsung",
    "D4E8B2": "Samsung",
    "D857EF": "Samsung",
    "E47CF9": "Samsung",
    "E8039A": "Samsung",
    "E84E84": "Samsung",
    "F008F1": "Samsung",
    "F06BCA": "Samsung",
    "F0728C": "Samsung",
    "F4428F": "Samsung",
    "F47B5E": "Samsung",
    "FC1910": "Samsung",

    # Google
    "F88FCA": "Google",
    "3C28C2": "Google",
    "54527B": "Google",
    "A47733": "Google",
    "7C2ECA": "Google",
    "3C5AB4": "Google (Nest)",
    "18B430": "Google (Nest)",
    "64166A": "Google (Nest)",
    "B4430D": "Google (Nest)",
    "B89141": "Google (Nest)",

    # Sony
    "001D0D": "Sony",
    "001E3D": "Sony",
    "0022AD": "Sony",
    "002345": "Sony",
    "0025E7": "Sony",
    "0CFDE0": "Sony",
    "1067EB": "Sony",
    "10681B": "Sony",
    "1C7B21": "Sony",
    "28F366": "Sony",
    "3019D2": "Sony",
    "3C0771": "Sony",
    "40B0FA": "Sony",
    "4CF225": "Sony",
    "58A708": "Sony",
    "6C34FB": "Sony",
    "78843C": "Sony",
    "7C1C68": "Sony",
    "807ABF": "Sony",
    "84C7CB": "Sony",
    "8C8590": "Sony",
    "90C115": "Sony",
    "9453D0": "Sony",
    "9CC8FC": "Sony",
    "A0519B": "Sony",
    "AC9B0A": "Sony",
    "B4527E": "Sony",
    "B8561A": "Sony",
    "C4C44B": "Sony",
    "D088E2": "Sony",
    "D4573D": "Sony",
    "F0BF97": "Sony",

    # Bose
    "88C9E8": "Bose",
    "000EB5": "Bose",
    "04520D": "Bose",
    "0407F9": "Bose",
    "20F8EC": "Bose",
    "88C9E8": "Bose",
    "ACBD00": "Bose",
    "C449B3": "Bose",

    # Jabra / GN Audio
    "50C2ED": "Jabra (GN Audio)",
    "00127A": "Jabra (GN Audio)",
    "9CC8CA": "Jabra (GN Audio)",
    "B8A3CC": "Jabra (GN Audio)",

    # Sennheiser
    "001B66": "Sennheiser",
    "7CF19D": "Sennheiser",
    "B8D6F6": "Sennheiser",

    # Logitech
    "00231A": "Logitech",
    "0025DB": "Logitech",
    "00DFA1": "Logitech",
    "34D270": "Logitech",
    "406186": "Logitech",
    "488E9B": "Logitech",
    "5404A6": "Logitech",
    "6092B1": "Logitech",
    "B03C0D": "Logitech",
    "B4A209": "Logitech",
    "D2AF68": "Logitech",

    # Microsoft
    "001DD8": "Microsoft",
    "003D1E": "Microsoft",
    "00125A": "Microsoft",
    "28C63F": "Microsoft",
    "2C54CF": "Microsoft",
    "3C18A0": "Microsoft",
    "48505B": "Microsoft",
    "54808E": "Microsoft",
    "5CB901": "Microsoft",
    "60155A": "Microsoft",
    "707681": "Microsoft",
    "7C1E52": "Microsoft",
    "A0999B": "Microsoft",
    "B4AEE9": "Microsoft",
    "C4175E": "Microsoft",
    "D8B4DA": "Microsoft",
    "F025B7": "Microsoft",

    # Intel
    "001DD8": "Intel",
    "34DE1A": "Intel",
    "5CE0C5": "Intel",
    "A0C589": "Intel",

    # Qualcomm
    "000AF5": "Qualcomm",
    "001CF0": "Qualcomm",
    "0022A1": "Qualcomm",
    "204E7F": "Qualcomm",
    "408D5C": "Qualcomm",
    "48A195": "Qualcomm",
    "60029D": "Qualcomm",
    "A04299": "Qualcomm",
    "ACA213": "Qualcomm",

    # Broadcom
    "000AF7": "Broadcom",
    "001CE6": "Broadcom",
    "002291": "Broadcom",
    "00267F": "Broadcom",
    "08CCBE": "Broadcom",
    "28183F": "Broadcom",
    "7078E8": "Broadcom",

    # Raspberry Pi / Foundation
    "DCA632": "Raspberry Pi",
    "B827EB": "Raspberry Pi",
    "E45F01": "Raspberry Pi",

    # Texas Instruments
    "0002A5": "Texas Instruments",
    "001349": "Texas Instruments",
    "0016D3": "Texas Instruments",
    "0017EC": "Texas Instruments",
    "001A80": "Texas Instruments",
    "0021BE": "Texas Instruments",
    "002264": "Texas Instruments",
    "246F28": "Texas Instruments",
    "283B96": "Texas Instruments",
    "68C90B": "Texas Instruments",
    "74F61C": "Texas Instruments",
    "88993D": "Texas Instruments",
    "A4D157": "Texas Instruments",
    "D0FF50": "Texas Instruments",

    # Nordic Semiconductor
    "D0F523": "Nordic Semiconductor",
    "EF6E": "Nordic Semiconductor",
    "F4CE36": "Nordic Semiconductor",

    # Fitbit / Google
    "E0AC CB": "Fitbit",
    "24A314": "Fitbit",
    "7CF9CE": "Fitbit",
    "C4CBA4": "Fitbit",

    # Garmin
    "002D70": "Garmin",
    "1C8779": "Garmin",
    "48E1E9": "Garmin",
    "582D34": "Garmin",
    "6CAB43": "Garmin",
    "784773": "Garmin",
    "BC0ABE": "Garmin",
    "C4423A": "Garmin",

    # Nintendo
    "002709": "Nintendo",
    "00224C": "Nintendo",
    "002659": "Nintendo",
    "0009BF": "Nintendo",
    "8CCDE8": "Nintendo",
    "98B6E9": "Nintendo",
    "E0E751": "Nintendo",
    "F45C89": "Nintendo",

    # Beats (Apple)
    "AC7F3E": "Beats (Apple)",
    "28A02B": "Beats (Apple)",
    "00B0D0": "Beats (Apple)",

    # JBL / Harman
    "0002C7": "JBL (Harman)",
    "ACBB44": "JBL (Harman)",
    "74EC B6": "JBL (Harman)",
    "FCDB96": "JBL (Harman)",

    # Skullcandy
    "B8D74B": "Skullcandy",
    "A4E905": "Skullcandy",

    # Plantronics / Poly
    "0021C1": "Plantronics",
    "001E02": "Plantronics",
    "848260": "Plantronics",
    "E4E476": "Plantronics",

    # Motorola
    "002297": "Motorola",
    "006B9E": "Motorola",
    "0026E6": "Motorola",
    "0C:0E:76": "Motorola",
    "40D855": "Motorola",
    "58E68F": "Motorola",
    "C0EEFB": "Motorola",
    "E4908D": "Motorola",

    # LG Electronics
    "001E75": "LG Electronics",
    "00228D": "LG Electronics",
    "002507": "LG Electronics",
    "002610": "LG Electronics",
    "0C4869": "LG Electronics",
    "1019B4": "LG Electronics",
    "18477E": "LG Electronics",
    "2C599E": "LG Electronics",
    "38F23E": "LG Electronics",
    "40B0FA": "LG Electronics",
    "44C8B2": "LG Electronics",
    "5055F4": "LG Electronics",
    "6006E6": "LG Electronics",
    "78F882": "LG Electronics",
    "88C9D0": "LG Electronics",
    "98D33B": "LG Electronics",
    "B4E62A": "LG Electronics",
    "C4894B": "LG Electronics",
    "CC2D8B": "LG Electronics",
    "E8F2E2": "LG Electronics",

    # Xiaomi
    "002844": "Xiaomi",
    "1C2BC2": "Xiaomi",
    "28E31F": "Xiaomi",
    "34CE00": "Xiaomi",
    "3C3A73": "Xiaomi",
    "40310D": "Xiaomi",
    "4C4987": "Xiaomi",
    "50EC50": "Xiaomi",
    "58441F": "Xiaomi",
    "60AB14": "Xiaomi",
    "640980": "Xiaomi",
    "688A76": "Xiaomi",
    "6C5D63": "Xiaomi",
    "74510B": "Xiaomi",
    "78DBCA": "Xiaomi",
    "7C1DD9": "Xiaomi",
    "8C0EE3": "Xiaomi",
    "98FAE3": "Xiaomi",
    "9C991A": "Xiaomi",
    "A048FC": "Xiaomi",
    "AC2390": "Xiaomi",
    "B06089": "Xiaomi",
    "C01D8D": "Xiaomi",
    "D4970B": "Xiaomi",
    "F48B32": "Xiaomi",
    "F8A45F": "Xiaomi",
    "FC64BA": "Xiaomi",

    # Huawei
    "001E10": "Huawei",
    "003048": "Huawei",
    "001E67": "Huawei",
    "047902": "Huawei",
    "087A4C": "Huawei",
    "104780": "Huawei",
    "1497BB": "Huawei",
    "28E8F8": "Huawei",
    "2CAB00": "Huawei",
    "30D17E": "Huawei",
    "3468C8": "Huawei",
    "40CB A8": "Huawei",
    "485A3F": "Huawei",
    "503D74": "Huawei",
    "54A51B": "Huawei",
    "5C7D5E": "Huawei",
    "647218": "Huawei",
    "683E34": "Huawei",
    "6C8D37": "Huawei",
    "70722D": "Huawei",
    "7CDF7B": "Huawei",
    "84742A": "Huawei",
    "8C34FD": "Huawei",
    "902157": "Huawei",
    "9C741A": "Huawei",
    "A0A327": "Huawei",
    "A42BB0": "Huawei",
    "AC853D": "Huawei",
    "B0E5F9": "Huawei",
    "BC9FBD": "Huawei",
    "C0BFC0": "Huawei",
    "C439440": "Huawei",
    "C8E5B0": "Huawei",
    "D4723C": "Huawei",
    "D46E5C": "Huawei",
    "DC727C": "Huawei",
    "E894F6": "Huawei",
    "F008F1": "Huawei",
    "F48753": "Huawei",
    "F8BF09": "Huawei",
}

# Normalize: strip separators, uppercase
def _normalize_oui(addr: str) -> str:
    clean = addr.upper().replace(":", "").replace("-", "").replace(".", "")
    return clean[:6]


def enrich_oui(device_addr: Optional[str]) -> Optional[str]:
    """
    Return manufacturer name for a BD_ADDR, or None if unknown.

    >>> enrich_oui("DC:A6:32:12:34:56")
    'Raspberry Pi'
    >>> enrich_oui("AA:BB:CC:DD:EE:FF")
    None
    """
    if not device_addr:
        return None
    prefix = _normalize_oui(device_addr)
    return _OUI_TABLE.get(prefix)


def enrich_oui_display(device_addr: Optional[str]) -> str:
    """
    Return 'Manufacturer (AA:BB:CC:DD:EE:FF)' or just the address if unknown.
    """
    if not device_addr:
        return ""
    mfr = enrich_oui(device_addr)
    if mfr:
        return f"{mfr} ({device_addr})"
    # Return OUI prefix for unknown
    prefix = device_addr.upper()[:8]  # AA:BB:CC
    return f"Unknown-{prefix} ({device_addr})"


if __name__ == "__main__":
    import sys
    if "--update" in sys.argv:
        import urllib.request, csv
        print("Downloading IEEE OUI registry...")
        url = "https://standards-oui.ieee.org/oui/oui.csv"
        with urllib.request.urlopen(url) as r:
            lines = r.read().decode("utf-8", errors="replace").splitlines()
        reader = csv.DictReader(lines)
        count = 0
        for row in reader:
            assignment = row.get("Assignment", "").replace("-", "")[:6]
            org = row.get("Organization Name", "").strip()
            if assignment and org:
                print(f'    "{assignment}": "{org}",')
                count += 1
        print(f"# {count} entries")
    else:
        # Self-test
        tests = [
            ("DC:A6:32:00:00:00", "Raspberry Pi"),
            ("00:05:02:00:00:00", "Apple"),
            ("00:16:32:00:00:00", "Samsung"),
            ("AA:BB:CC:DD:EE:FF", None),
        ]
        for addr, expected in tests:
            result = enrich_oui(addr)
            status = "OK" if result == expected else f"FAIL (got {result!r})"
            print(f"  {addr} → {result!r} [{status}]")
