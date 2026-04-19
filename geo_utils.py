import geoip2.database

import os



# Update this path to where your .mmdb file actually is

DB_PATH = '/home/vinayak/honeypot_project/data/GeoLite2-City.mmdb'



def get_geo_data(ip):

    """

    Local-only lookup. 

    Heatmap logic: Returns None for local IPs.

    """

    # 1. Identify Local/Internal Traffic

    if (ip.startswith("10.") or ip.startswith("192.168.") or 

        ip.startswith("127.") or ip.startswith("172.")):

        return None, None, "India", "Local_Network"



    # 2. Local Database Lookup for Global IPs

    if not os.path.exists(DB_PATH):

        print(f"[!] GeoIP Database not found at {DB_PATH}")

        return None, None, "Unknown", "Unknown"



    try:

        with geoip2.database.Reader(DB_PATH) as reader:

            response = reader.city(ip)

            return (

                response.location.latitude,

                response.location.longitude,

                response.country.name,

                response.city.name

            )

    except Exception as e:

        # If the IP isn't in the database (like some VPNs/Tunnels), return None

        return None, None, "Unknown", "Unknown"