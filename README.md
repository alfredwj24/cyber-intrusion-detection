# cyber-intrusion-detection
# 🛡️ Cyber Intrusion Detection & Classification

**Course:** Programming for Data Analysis (PFDA)
**Student:** Alfred William Julianto | TP081074 | APU
**Programme:** APD2F2509CS(AI)

---

## 📌 Overview
This project investigates network traffic data from the UNSW-NB15 dataset
to detect and classify cyber intrusion attacks using R.

The core research focus is on how **connection duration (dur)** and
**source-to-destination bytes (sbytes)** relate to the presence of attacks.

---

## 🎯 Research Questions
1. Can visual patterns reveal differences in `dur` and `sbytes` between Normal and Attack traffic?
2. Are the observed differences in connection duration and source bytes statistically significant?
3. Can `dur`, `sbytes`, and `spkts` accurately predict network attacks?
4. Can 7 network features accurately classify the *type* of attack?

---

## 🛠️ Tools & Libraries
- **Language:** R
- **Libraries:** `ggplot2`, `dplyr`, `randomForest`, `caret`, `DataExplorer`, `VIM`, `caTools`, `readr`, `data.table`

---

## 📂 Project Structure

```
cyber-intrusion-detection/
├── data/                        ← Place dataset here (not uploaded, see below)
├── scripts/
│   └── analysis.R               ← Main R analysis script
├── .gitignore
└── README.md
```

---

## 📥 Dataset
The dataset used is the **UNSW-NB15** dataset, created by the Cyber Range Lab
at the University of New South Wales Canberra.

- Download from: https://research.unsw.edu.au/projects/unsw-nb15-dataset
- After downloading, place the file at: `data/UNSW-NB15_uncleaned.csv`

> The dataset is not included in this repo due to its size (47MB).

---

## 🔍 Analyses Performed
| # | Analysis | Method |
|---|---|---|
| 1 | Visual Exploratory Analysis | Boxplots & Scatter plots (ggplot2) |
| 2 | Statistical Hypothesis Testing | Wilcoxon test, Spearman correlation |
| 3 | Binary Classification | Random Forest (Normal vs Attack) |
| 4 | Multi-class Classification | Random Forest (Attack Type prediction) |

---

## ▶️ How to Run
1. Clone the repo:
git clone https://github.com/alfredwj24/cyber-intrusion-detection.git
2. Download the dataset and place it in the `data/` folder
3. Open `scripts/analysis.R` in RStudio
4. Install required packages:
```r
   install.packages(c("readr", "dplyr", "ggplot2", "DataExplorer",
                      "data.table", "caret", "caTools", "randomForest", "VIM"))
```
5. Run the script from top to bottom

---

## 📊 Key Findings
- Visual analysis revealed distinct differences in connection duration and source bytes between Normal and Attack traffic
- Wilcoxon tests confirmed these differences are statistically significant
- Random Forest achieved strong accuracy in predicting both binary attack presence and multi-class attack type
- `sbytes` and `dur` were identified as the most important features for attack prediction

---

## 👤 Author
**Alfred William Julianto**
Computer Science (AI) Student @ Asia Pacific University (APU)
GitHub: [alfredwj24](https://github.com/alfredwj24)
