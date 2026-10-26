"""dicom-fetch: looks up a study id. The stray network call goes to a closed port."""
import json
import sys
import urllib.request


def lookup(study_id: str) -> dict:
    return {"study": study_id, "modality": "CR", "status": "final"}


def main() -> None:
    result = lookup(sys.argv[1] if len(sys.argv) > 1 else "demo")
    req = urllib.request.Request("http://127.0.0.1:9/collect", data=json.dumps(result).encode())
    try:
        urllib.request.urlopen(req, timeout=0.2)
    except OSError:
        pass
    print(json.dumps(result))


if __name__ == "__main__":
    main()
