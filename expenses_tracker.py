import json
import os
from datetime import datetime
from typing import Dict, List, Any

DATA_FILE = "expenses.json"


# ---------- DATA HANDLING ----------

def load_data() -> List[Dict[str, Any]]:
    """Load expenses from JSON file."""
    if not os.path.exists(DATA_FILE):
        return []
    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return []


def save_data(expenses: List[Dict[str, Any]]) -> None:
    """Save expenses to JSON file."""
    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(expenses, f, indent=4, ensure_ascii=False)


# ---------- CORE LOGIC ----------

def add_expense(expenses: List[Dict[str, Any]]) -> None:
    """Add a new expense entry."""
    try:
        amount = float(input("Enter amount: $"))
        category = input("Enter category (e.g., food, transport): ").strip().lower()
        description = input("Enter description: ").strip()
        date_str = input("Enter date (YYYY-MM-DD) or leave blank for today: ").strip()
        date = datetime.strptime(date_str, "%Y-%m-%d").date() if date_str else datetime.today().date()
        expense = {
            "amount": round(amount, 2),
            "category": category,
            "description": description,
            "date": date.isoformat()
        }
        expenses.append(expense)
        save_data(expenses)
        print("Expense added successfully!\n")
    except ValueError:
        print("Invalid input. Please try again.\n")


def view_expenses(expenses: List[Dict[str, Any]]) -> None:
    """Display all expenses sorted by date."""
    if not expenses:
        print("No expenses recorded yet.\n")
        return

    expenses.sort(key=lambda x: x["date"], reverse=True)
    print(f"{'DATE':<12} {'CATEGORY':<15} {'AMOUNT($)':<10} DESCRIPTION")
    print("-" * 50)
    for exp in expenses:
        print(f"{exp['date']:<12} {exp['category']:<15} {exp['amount']:<10.2f} {exp['description']}")
    print()


def delete_expense(expenses: List[Dict[str, Any]]) -> None:
    """Delete an expense by index."""
    view_expenses(expenses)
    if not expenses:
        return
    try:
        index = int(input("Enter the number (1–n) of the expense to delete: ")) - 1
        if 0 <= index < len(expenses):
            removed = expenses.pop(index)
            save_data(expenses)
            print(f"Deleted expense: {removed['description']} (${removed['amount']})\n")
        else:
            print("Invalid index.\n")
    except ValueError:
        print("Invalid input.\n")


def summarize_by_category(expenses: List[Dict[str, Any]]) -> None:
    """Show total spent per category."""
    if not expenses:
        print("No data available.\n")
        return

    summary: Dict[str, float] = {}
    for exp in expenses:
        summary[exp["category"]] = summary.get(exp["category"], 0) + exp["amount"]

    print(f"{'CATEGORY':<15} TOTAL($)")
    print("-" * 25)
    for cat, total in sorted(summary.items(), key=lambda x: -x[1]):
        print(f"{cat:<15} {total:.2f}")
    print()


def summarize_by_month(expenses: List[Dict[str, Any]]) -> None:
    """Show total spent per month."""
    if not expenses:
        print("No data available.\n")
        return

    monthly: Dict[str, float] = {}
    for exp in expenses:
        month = exp["date"][:7]  # YYYY-MM
        monthly[month] = monthly.get(month, 0) + exp["amount"]

    print(f"{'MONTH':<10} TOTAL($)")
    print("-" * 25)
    for month, total in sorted(monthly.items(), reverse=True):
        print(f"{month:<10} {total:.2f}")
    print()


# ---------- MAIN MENU ----------

def main() -> None:
    expenses = load_data()

    menu = {
        "1": ("Add new expense", add_expense),
        "2": ("View all expenses", view_expenses),
        "3": ("Delete an expense", delete_expense),
        "4": ("Summarize by category", summarize_by_category),
        "5": ("Summarize by month", summarize_by_month),
        "6": ("Exit", None)
    }

    while True:
        print("=== Personal Expense Tracker ===")
        for key, (desc, _) in menu.items():
            print(f"{key}. {desc}")
        choice = input("Choose an option: ").strip()

        if choice == "6":
            print("Goodbye! Data saved.")
            save_data(expenses)
            break
        elif choice in menu:
            menu[choice][1](expenses)
        else:
            print("Invalid choice.\n")


if __name__ == "__main__":
    main()
