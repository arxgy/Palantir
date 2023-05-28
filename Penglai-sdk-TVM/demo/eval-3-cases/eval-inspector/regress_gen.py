import seaborn as sns
import pandas as pd
import matplotlib.pyplot as plt

sns.set()
data = pd.read_csv('data.csv')
g = sns.regplot(x="#Page", y="#Cycle", data=data)
plt.savefig('regress_gen.png')