import os
import json
from pprint import pprint

MONGO_URI = os.getenv('GENTRIAGE_MONGO_URI', 'mongodb://admin:password@localhost:27017')
TASKS_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'apks', 'tasks.json')

def main():
    try:
        from pymongo import MongoClient
    except Exception as e:
        print('pymongo not installed. Install with: pip install pymongo')
        raise

    client = MongoClient(MONGO_URI)
    db = client.gentriage
    coll = db.tasks

    with open(TASKS_PATH, 'r', encoding='utf-8') as f:
        data = json.load(f)

    docs = []
    for k, v in data.items():
        docs.append(v)

    if not docs:
        print('No tasks to migrate')
        return

    inserted = 0
    for doc in docs:
        coll.replace_one({'task_id': doc.get('task_id')}, doc, upsert=True)
        inserted += 1

    print(f'Migrated {inserted} tasks to MongoDB at {MONGO_URI}')

if __name__ == '__main__':
    main()
