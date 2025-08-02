def export_logs_to_csv():
    try:
        with open("network_log_fixed.json", "r") as f:
            logs = json.load(f)

        # Collect all unique keys from all logs
        fieldnames = sorted(set().union(*(log.keys() for log in logs)))

        with open("exported_logs.csv", "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for log in logs:
                writer.writerow(log)

        messagebox.showinfo("Success", "Logs exported to exported_logs.csv")

    except Exception as e:
        messagebox.showerror("Error", f"Export failed:\n{str(e)}")
