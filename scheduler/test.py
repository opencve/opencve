import os, json
kind = "nvd"

def write_cve(cve_id, payload):
    path = f"/tmp/{cve_id}.json"

    if not os.path.exists(path):
        source_payload = {kind: payload}
        print(source_payload)
        with open(path, "w") as f:
            json.dump(source_payload, f, indent=2, sort_keys=True)
    else:
        with open(path, "r") as f:
            current_data = json.load(f)
            print(current_data)

        # Append the new data
        with open(path, "w") as f:
            current_data[kind] = payload
            json.dump(current_data, f, indent=2, sort_keys=True)

write_cve("CVE-1234", {"foo": "datafromnvd"})
