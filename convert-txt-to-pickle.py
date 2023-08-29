import os
import pickle

count = 0
integer_count = 0
dbname = "%02d" % integer_count
address_set = set()
maxCount = 1000000
MAX_FILES = 5

DATABASE = r'database/DATABASE-LOYCE'

def is_valid_pickle(data):
    try:
        pickle.loads(data)
        return True
    except pickle.UnpicklingError:
        return False

with open("addresses_with_balance.txt", "r") as f_obj:
    addresses = f_obj.readlines()

print(f"Writing to {DATABASE}{dbname}.pickle")

for address in addresses:
    if address.startswith('1'):
        address_set.add(address.strip())
        count += 1
        print("\r" + str(count) + " " + str(address.strip()), end="")
    if count >= maxCount:
        filepath = os.path.join(DATABASE, f"{dbname}.pickle")
        with open(filepath, "ab") as fileDB:
            data = pickle.dumps(address_set, protocol=pickle.HIGHEST_PROTOCOL)
            if is_valid_pickle(data):
                fileDB.write(data)
        address_set = set()
        count = 0
        integer_count += 1
        dbname = "%02d" % integer_count
        print("\nWriting to " + DATABASE + dbname + ".pickle")

filepath = os.path.join(DATABASE, f"{dbname}.pickle")
with open(filepath, "ab") as fileDB:
    data = pickle.dumps(address_set, protocol=pickle.HIGHEST_PROTOCOL)
    if is_valid_pickle(data):
        fileDB.write(data)

print("\n")

# Reading and combining the databases
database_partitions = [set() for _ in range(MAX_FILES)]
count = len(os.listdir(DATABASE))
half = count // 2
quarter = half // 2

for c, p in enumerate(os.listdir(DATABASE)):
    print('\rReading database: ' + str(c + 1) + '/' + str(count), end=' ')
    with open(os.path.join(DATABASE, p), 'rb') as file:
        try:
            data = pickle.load(file)
            if c == 20:
                database_partitions[4] = database_partitions[4] | data
                continue
            if c < half:
                if c < quarter:
                    database_partitions[0] = database_partitions[0] | data
                else:
                    database_partitions[1] = database_partitions[1] | data
            elif c < half + quarter:
                database_partitions[2] = database_partitions[2] | data
            else:
                database_partitions[3] = database_partitions[3] | data
        except Exception as e:
            print("Error unpickling:", e)

print('DONE')

print(f'Database size: {str(sum(len(i) for i in database_partitions))}')