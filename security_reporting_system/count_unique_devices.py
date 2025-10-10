# import json
#
# def list_unique_objects(patch_file1: str, patch_file2: str, output_file: str):
#     # Load first file
#     with open(patch_file1, "r", encoding="utf-8") as f:
#         data1 = json.load(f)
#
#     # Load second file
#     with open(patch_file2, "r", encoding="utf-8") as f:
#         data2 = json.load(f)
#
#     # Build lookup by ID
#     objs1 = {item.get("id"): item for item in data1 if "id" in item}
#     objs2 = {item.get("id"): item for item in data2 if "id" in item}
#
#     ids1, ids2 = set(objs1.keys()), set(objs2.keys())
#
#     # Unique IDs
#     only_in_1 = ids1 - ids2
#     only_in_2 = ids2 - ids1
#
#     # Collect unique objects
#     unique_objects = {
#         f"unique_in_{patch_file1}": [objs1[i] for i in only_in_1],
#         f"unique_in_{patch_file2}": [objs2[i] for i in only_in_2]
#     }
#
#     # Save to new JSON file
#     with open(output_file, "w", encoding="utf-8") as f:
#         json.dump(unique_objects, f, indent=2)
#
#     print("=== Unique Objects Summary ===")
#     print(f"Objects only in {patch_file1}: {len(only_in_1)}")
#     print(f"Objects only in {patch_file2}: {len(only_in_2)}")
#     print(f"Results saved to {output_file}")
#
# if __name__ == "__main__":
#     list_unique_objects("patch1.json", "patch3.json", "patch_new.json")




import json
from datetime import datetime, timezone

def filter_by_august(file_path: str, output_file: str = "result.json"):
    # Define start and end of August 2025 in UTC
    start = datetime(2025, 8, 1, 0, 0, 0, tzinfo=timezone.utc).timestamp()
    end = datetime(2025, 8, 31, 23, 59, 59, tzinfo=timezone.utc).timestamp()

    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # Filter objects within the range
    filtered = [
        obj for obj in data
        if start <= obj.get("timestamp", 0) <= end
    ]

    # Save results into os_patch_result.json
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(filtered, f, indent=2)

    print(f"Filtered {len(filtered)} objects written to {output_file}")


if __name__ == "__main__":
    filter_by_august("patch1.json")
# import json
#
# def count_unique_ids(file_path: str):
#     with open(file_path, "r", encoding="utf-8") as f:
#         data = json.load(f)
#
#     # Collect IDs
#     ids = {item.get("productIdentifier") for item in data if "productIdentifier" in item}
#
#     print("=== Unique ID Summary ===")
#     print(f"Total unique IDs: {len(ids)}")
#
#     return ids  # optional if you want to reuse the set
#
#
# if __name__ == "__main__":
#     count_unique_ids("patch1.json")
