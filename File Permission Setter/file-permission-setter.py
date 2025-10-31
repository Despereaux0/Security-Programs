import os
 
def set_file_permissions(file_path, permissions):
    try:
        os.chmod(file_path, permissions)
        print(f"File permissions for '{file_path}' have been set.")
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except Exception as e:
        print(f"Error: {e}")
 
# Example usage:
file_path = input("Enter File Path: ")
 
#'/path/to/your/file.txt'
 
# Set file permissions (e.g., 0o755 for read, write, and execute for the owner, read, and execute for the group and others)
#read=4, write=2 and ecxecute=1
#permissions = 0o755
permissions_str = input("Enter File permissions: ")
permissions = int(permissions_str, 8)
 
set_file_permissions(file_path, permissions)
