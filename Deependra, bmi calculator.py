import tkinter as tk
from tkinter import messagebox
import csv
import os
import matplotlib.pyplot as plt

DATA_FILE = "bmi_history.csv"


def calculate_bmi(weight, height):
    return weight / (height ** 2)


def classify_bmi(bmi):
    if bmi < 18.5:
        return "Underweight"
    elif bmi < 25:
        return "Normal weight"
    elif bmi < 30:
        return "Overweight"
    else:
        return "Obese"


def save_data(name, bmi):
    with open(DATA_FILE, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([name, bmi])


def show_graph(name):
    if not os.path.exists(DATA_FILE):
        messagebox.showinfo("No Data", "No history found.")
        return

    dates, bmis = [], []
    with open(DATA_FILE, "r") as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] == name:
                bmis.append(float(row[1]))
                dates.append(len(bmis))

    if not bmis:
        messagebox.showinfo("No Data", "No data found for this user.")
        return

    plt.plot(dates, bmis, marker='o')
    plt.title(f"BMI Trend for {name}")
    plt.xlabel("Entries")
    plt.ylabel("BMI")
    plt.show()


def calculate_and_display():
    try:
        name = name_entry.get().strip()
        weight = float(weight_entry.get())
        height = float(height_entry.get())

        if not name or weight <= 0 or height <= 0:
            raise ValueError

        bmi = calculate_bmi(weight, height)
        category = classify_bmi(bmi)
        result_label.config(text=f"BMI: {bmi:.2f} ({category})")

        save_data(name, bmi)

    except ValueError:
        messagebox.showerror("Invalid Input", "Please enter valid name, weight, and height.")


# --- GUI Setup ---
root = tk.Tk()
root.title("BMI Calculator")

tk.Label(root, text="Name:").grid(row=0, column=0)
tk.Label(root, text="Weight (kg):").grid(row=1, column=0)
tk.Label(root, text="Height (m):").grid(row=2, column=0)

name_entry = tk.Entry(root)
weight_entry = tk.Entry(root)
height_entry = tk.Entry(root)
name_entry.grid(row=0, column=1)
weight_entry.grid(row=1, column=1)
height_entry.grid(row=2, column=1)

tk.Button(root, text="Calculate", command=calculate_and_display).grid(row=3, column=0, columnspan=2)
tk.Button(root, text="Show History", command=lambda: show_graph(name_entry.get())).grid(row=4, column=0, columnspan=2)

result_label = tk.Label(root, text="")
result_label.grid(row=5, column=0, columnspan=2)

root.mainloop()
