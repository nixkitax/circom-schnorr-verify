import json, os

def create_json(result):
    output_file_path = os.path.join("../inputs/schnorrSign", "input.json")
    with open(output_file_path, "w") as output_file:
        json.dump(result, output_file, indent=4)   
         
    print("[i] made input file for circom succesfully")

