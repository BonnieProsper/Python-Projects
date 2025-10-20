import json
from datetime import date, timedelta

DATA_FILE = "habits.json"


# ---------------------------- Utility Functions ---------------------------- #
def load_data(filename=DATA_FILE):
    """Load habit data from a JSON file."""
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def save_data(data, filename=DATA_FILE):
    """Save habit data to a JSON file."""
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)


def days_between(d1, d2):
    """Return the number of days between two YYYY-MM-DD date strings."""
    return (date.fromisoformat(d1) - date.fromisoformat(d2)).days


# ---------------------------- Habit Management ----------------------------- #
def add_habit(data):
    """Add a new habit to the tracker."""
    name = input("Habit name: ").strip().title()
    if name in data:
        print("Habit already exists.")
        return

    priority = input("Priority (High/Med/Low): ").strip().capitalize()
    if priority not in {"High", "Med", "Low"}:
        priority = "Med"

    data[name] = {
        "priority": priority,
        "streak": 0,
        "last_done": None,
        "completed": 0,
        "missed": 0
    }
    print(f"✅ Added habit '{name}' with {priority} priority.")


def mark_complete(data):
    """Mark a habit as completed for today."""
    habits = list(data.keys())
    if not habits:
        print("No habits to mark yet.")
        return

    print("\nSelect a habit to mark as done:")
    for i, h in enumerate(habits, start=1):
        print(f"{i}. {h}")

    try:
        choice = int(input("Enter number: "))
        name = habits[choice - 1]
    except (ValueError, IndexError):
        print("Invalid selection.")
        return

    today = date.today().isoformat()
    habit = data[name]

    if habit["last_done"] == today:
        print(f"'{name}' already completed today.")
        return

    if habit["last_done"]:
        gap = days_between(today, habit["last_done"])
        if gap == 1:
            habit["streak"] += 1
        elif gap > 1:
            habit["streak"] = 1
            habit["missed"] += gap - 1
    else:
        habit["streak"] = 1

    habit["completed"] += 1
    habit["last_done"] = today
    print(f"🎯 '{name}' marked complete. Current streak: {habit['streak']} days!")


def view_habits(data):
    """Display all habits with stats."""
    if not data:
        print("No habits found.")
        return

    sort_key = input("Sort by (name/streak/priority)? ").strip().lower()
    if sort_key == "streak":
        habits = sorted(data.items(), key=lambda x: x[1]["streak"], reverse=True)
    elif sort_key == "priority":
        order = {"High": 0, "Med": 1, "Low": 2}
        habits = sorted(data.items(), key=lambda x: order[x[1]["priority"]])
    else:
        habits = sorted(data.items())

    print("\nYour Habits:")
    print("-" * 60)
    for name, h in habits:
        print(
            f"{name:15} | Priority: {h['priority']:4} | "
            f"Streak: {h['streak']:2} | Completed: {h['completed']:3} | Missed: {h['missed']:3}"
        )
    print("-" * 60)


def remove_habit(data):
    """Remove a habit."""
    name = input("Habit to remove: ").strip().title()
    if name in data:
        del data[name]
        print(f"❌ Removed '{name}'.")
    else:
        print("Habit not found.")


# ------------------------------- Main Program ------------------------------ #
def main():
    data = load_data()
    print("📘 Welcome to the Smart Habit Tracker!")

    while True:
        print("\nMenu:")
        print("1. View habits")
        print("2. Add habit")
        print("3. Mark complete")
        print("4. Remove habit")
        print("5. Save & Quit")

        choice = input("Select an option: ").strip()
        if choice == "1":
            view_habits(data)
        elif choice == "2":
            add_habit(data)
        elif choice == "3":
            mark_complete(data)
        elif choice == "4":
            remove_habit(data)
        elif choice == "5":
            save_data(data)
            print("💾 Data saved. Goodbye!")
            break
        else:
            print("Invalid option. Try again.")


if __name__ == "__main__":
    main()
