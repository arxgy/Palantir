import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from matplotlib import rc
# Specify the path to your CSV file
native_csv = 'native.csv'
reusable_csv = 'reusable.csv'

# Reading the CSV file

# Displaying all entries

size_list = ['4','8','16','32','64','128','256','512',]
destroy_costs_native = []
create_costs_native = []
reset_costs_native = []
comm_costs_native = []
other_costs_native = []
total_costs_native = []

destroy_costs_reusable = []
create_costs_reusable = []
reset_costs_reusable = []
comm_costs_reusable = []
other_costs_reusable = []
total_costs_reusable = []
# Function to convert a HEX string column to DEC integers
def convert_hex_column_to_dec(column):
    return column.apply(lambda x: int(x, 16) if pd.notnull(x) else None)

# DESTROY, CREATE, RESET, COMMUNICATE, OTHER
# Convert all columns from HEX to DEC
df = pd.read_csv(native_csv, dtype=str)
for column in df.columns:
    df[column] = convert_hex_column_to_dec(df[column])
    destroy_cost = df[column][2] - df[column][1]
    create_cost = df[column][4] - df[column][3]
    reset_cost = 0
    comm_cost = (df[column][1] - df[column][0]) + (df[column][3] - df[column][2]) + (df[column][5] - df[column][4])
    total_cost = df[column][5] - df[column][0]
    other_cost = total_cost - (destroy_cost+create_cost+reset_cost+comm_cost)

    destroy_costs_native.append(destroy_cost)
    create_costs_native.append(create_cost)
    reset_costs_native.append(reset_cost)
    comm_costs_native.append(comm_cost)
    total_costs_native.append(total_cost)
    other_costs_native.append(other_cost)

df = pd.read_csv(reusable_csv, dtype=str)
for column in df.columns:
    df[column] = convert_hex_column_to_dec(df[column])
    destroy_cost = 0
    create_cost = 0
    reset_cost = df[column][2]
    comm_cost = df[column][1] - df[column][0]
    total_cost = df[column][3]
    other_cost = total_cost - (destroy_cost+create_cost+reset_cost+comm_cost)

    destroy_costs_reusable.append(destroy_cost)
    create_costs_reusable.append(create_cost)
    reset_costs_reusable.append(reset_cost)
    comm_costs_reusable.append(comm_cost)
    other_costs_reusable.append(other_cost)
    total_costs_reusable.append(total_cost)

# Displaying the converted DataFrame
# print(df)
x = np.arange(len(size_list))
# x = list(range(len(size_list)))
width = 0.32
# plt.rcParams["font.family"] = "Times New Roman"

fig, ax = plt.subplots()

ax.set_xticks(x)
ax.set_xticklabels(size_list)

plt.yscale('log')
# y_ticks = np.logspace(7, 11, 5)
y_ticks = [10**7, 10**8, 10**9, 10**10, 5*10**10]
y_tick_labels = ['1', '10', '100', '1000', '']
plt.yticks(ticks=y_ticks, labels=y_tick_labels)  # Apply the custom ticks and labels
plt.ylim(10**7, 5*10**10)
plt.ylabel("Time ($10^7$ cycle)")
plt.xlabel("Heap Size (MiB)")
native_bottom_1 = destroy_costs_native
native_bottom_2 = np.add(native_bottom_1, create_costs_native)
native_bottom_3 = np.add(native_bottom_2, comm_costs_native)
# 574142
# 9999CC
plt.bar(x - width/2, destroy_costs_native, width=width, label='DESTROY', color="#9999CC")
plt.bar(x - width/2, create_costs_native, width=width, bottom=native_bottom_1, label='CREATE', color="#40908C")
plt.bar(x - width/2, comm_costs_native, width=width, bottom=native_bottom_2, label='Communication', color="#574142")
plt.bar(x - width/2, other_costs_native, width=width, bottom=native_bottom_3, label='Other', color="#FFD885")

reusable_bottom_1 = reset_costs_reusable
reusable_bottom_2 = np.add(reusable_bottom_1, comm_costs_reusable)
plt.bar(x + width/2, reset_costs_reusable, width=width, label='Reset', color='#00905B')
plt.bar(x + width/2, comm_costs_reusable, width=width, bottom=reusable_bottom_1, color="#574142")
plt.bar(x + width/2, other_costs_reusable, width=width, bottom=reusable_bottom_2, color="#FFD885")

lines, labels = ax.get_legend_handles_labels()
# plt.legend(loc='best')
ax2 = plt.twinx()
ax2.set_ylabel("Reset/Relaunch")

# ax.grid()
ax2.set_ylim([0,0.4])

ratio_list = [round(b/a, 3) for a, b in zip(total_costs_native, total_costs_reusable)]
plt.plot(size_list, ratio_list, marker='.', c = '#046ACA', ms=5, linewidth='1', label='Reset/Relaunch')
# for sz, r in zip(size_list, ratio_list): 
#     plt.text(sz, r+0.3, r, ha='center', va='bottom', fontsize=10)

lines2, labels2 = ax2.get_legend_handles_labels()
ax.legend(lines + lines2, labels + labels2, loc=0)

print(ratio_list)
# #F2855E
# plt.legend()
# plt.legend(loc='best')
plt.savefig('demo.pdf', format='pdf')
plt.show()