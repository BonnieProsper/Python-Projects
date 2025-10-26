import json
import os
import time
from datetime import datetime, timedelta

# -----------------------------
# Utility and Core Data Classes
# -----------------------------

class Task:
    """Represents a task with importance, urgency, and effort."""
    def __init__(self, name, deadline, importance, effort):
        self.name = name
        self.deadline = datetime.strptime(deadline, "%Y-%m-%d %H:%M")
        self.importance = importance        # 1–10
        self.effort = effort                # 1–10
        self.created = datetime.now()

    def time_left_hours(self):
        return max(0, (self.deadline - datetime.now()).total_seconds() / 3600)

    def to_dict(self):
        return {
            "name": self.name,
            "deadline": self.deadline.strftime("%Y-%m-%d %H:%M"),
            "importance": self.importance,
            "effort": self.effort,
            "created": self.created.strftime("%Y-%m-%d %H:%M:%S"),
        }

    @staticmethod
    def from_dict(data):
        t = Task(data["name"], data["deadline"], data["importance"], data["effort"])
        t.created = datetime.strptime(data["created"], "%Y-%m-%d %H:%M:%S")
        return t


# -----------------------------
# Decision Algorithm
# -----------------------------

class PriorityEngine:
    """Calculates priority scores using urgency, importance, effort, and fatigue."""
    def __init__(self, tasks):
        self.tasks = tasks

    def compute_priority(self, task, fatigue_level):
        hours_left = task.time_left_hours()

        # Normalize factors
        urgency_score = 10 if hours_left < 1 else max(1, 10 - (hours_left / 24))
        importance_score = task.importance
        effort_penalty = task.effort * (1 + fatigue_level / 10)

        # Weighted sum (custom logic)
        score = (importance_score * 1.5) + (urgency_score * 1.2) - (effort_penalty * 0.8)
        return max(score, 0)

    def suggest_order(self, fatigue_level):
        scored = []
        for task in self.tasks:
            score = self.compute_priority(task, fatigue_level)
            scored.append((task, round(score, 2)))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored


# -----------------------------
# Storage Manager
# -----------------------------

class Vault:
    """Handles JSON persistence of tasks."""
    FILE_NAME = "task_vault.json"

    def __init__(self):
        if not os.path.exists(self.FILE_NAME):
            with open(self.FILE_NAME, "w") as f:
                json.dump([], f)

    def load(self):
        with open(self.FILE_NAME, "r") as f:
            data = json.load(f)
        return [Task.from_dict(d) for d in data]

    def save(self, tasks):
        with open(self.FILE_NAME, "w") as f:
            json.dump([t.to_dict() for t in tasks], f, indent=2)


# -----------------------------
# Text-Based Interface
# -----------------------------

class SmartTaskCLI:
    def __init__(self):
        self.vault = Vault()
        self.tasks = self.vault.load()

    def run(self):
        while True:
            self.clear()
            print("==== SMART TASK PRIORITIZER ====\n")
            print("1. Add Task")
            print("2. View Tasks")
            print("3. Get Smart Schedule")
            print("4. Delete Task")
            print("5. Exit\n")

            choice = input("Choose an option: ").strip()
            if choice == "1":
                self.add_task()
            elif choice == "2":
                self.view_tasks()
            elif choice == "3":
                self.smart_schedule()
            elif choice == "4":
                self.delete_task()
            elif choice == "5":
                print("\nGoodbye! Stay productive.\n")
                break
            else:
                input("Invalid option. Press Enter to continue...")

    def add_task(self):
        print("\n--- Add a New Task ---")
        name = input("Task name: ").strip()
        deadline = input("Deadline (YYYY-MM-DD HH:MM): ").strip()
        importance = self.get_int("Importance (1–10): ", 1, 10)
        effort = self.get_int("Effort required (1–10): ", 1, 10)

        task = Task(name, deadline, importance, effort)
        self.tasks.append(task)
        self.vault.save(self.tasks)
        input("\nTask added successfully! Press Enter to continue...")

    def view_tasks(self):
        print("\n--- All Tasks ---\n")
        if not self.tasks:
            input("No tasks found. Press Enter to return...")
            return
        for i, t in enumerate(self.tasks, start=1):
            print(f"{i}. {t.name} | Due: {t.deadline} | Importance: {t.importance} | Effort: {t.effort}")
        input("\nPress Enter to return...")

    def smart_schedule(self):
        print("\n--- Smart Task Schedule ---")
        fatigue = self.get_int("How tired are you right now? (0–10): ", 0, 10)

        engine = PriorityEngine(self.tasks)
        ordered = engine.suggest_order(fatigue)

        if not ordered:
            input("No tasks found. Press Enter to return...")
            return

        print("\nRecommended order based on current fatigue:\n")
        for rank, (task, score) in enumerate(ordered, start=1):
            time_left = round(task.time_left_hours(), 1)
            print(f"{rank}. {task.name}  | Score: {score}  | Time left: {time_left} hrs")
        print("\nExplanation:")
        print("- Urgency increases as deadlines approach.")
        print("- High fatigue penalizes difficult tasks.")
        print("- Importance always weighs more heavily than effort.\n")

        input("Press Enter to return...")

    def delete_task(self):
        print("\n--- Delete a Task ---")
        if not self.tasks:
            input("No tasks to delete. Press Enter to return...")
            return
        self.view_tasks()
        idx = self.get_int("Enter task number to delete: ", 1, len(self.tasks))
        deleted = self.tasks.pop(idx - 1)
        self.vault.save(self.tasks)
        input(f"\nDeleted task: {deleted.name}\nPress Enter to continue...")

    @staticmethod
    def get_int(prompt, min_val, max_val):
        while True:
            try:
                val = int(input(prompt))
                if min_val <= val <= max_val:
                    return val
            except ValueError:
                pass
            print(f"Enter a number between {min_val} and {max_val}.")

    @staticmethod
    def clear():
        os.system('cls' if os.name == 'nt' else 'clear')


# -----------------------------
# Main Entry Point
# -----------------------------

if __name__ == "__main__":
    app = SmartTaskCLI()
    app.run()
