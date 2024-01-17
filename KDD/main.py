import pandas as pd
import numpy as np
import gzip
import requests
import matplotlib.pyplot as plt
import seaborn as sns

df = pd.read_csv("mid_processed_kdd.csv")
print(df.head())

fig, ax = plt.subplots(figsize=(15,5))
sns.countplot(x='Attack Type', data=df, ax=ax, palette='Greens_r', order=df['Attack Type'].value_counts().index,linewidth=0)
plt.show()
print('Top 3 the attack types are : ',df['Attack Type'].value_counts().index[:3].tolist())
