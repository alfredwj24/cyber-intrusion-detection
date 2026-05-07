# PFDA Assignment
# Cyber intrusion detection and classification
# Alfred William Julianto
# TP081074
# APD2F2509CS(AI)


# Load required libraries
library(readr)
library(dplyr)
library(ggplot2)
library(DataExplorer)
library(data.table)
library(caret)
library(caTools)
library(randomForest)
library(VIM)

# Objective: To investigate the impact of record total duration (dur) and source to destination transaction bytes (sbytes) towards presence of attack.
# Analysis 1: Can visual patterns reveal differences in dur and sbytes between Normal and Attack traffic?
# Analysis 2: Are the observed differences in connection duration and source bytes between Normal and Attack traffic statistically significant?
# Analysis 3: Can connection duration, source bytes, and source packet count accurately predict network attacks?
# Analysis 4: Can 7 network connection features accurately predict the category of attacks?

# Use decimal notation instead of scientific
options(scipen = 999)


# DATA LOADING

# Load dataset
df = read.csv('data/UNSW-NB15_uncleaned.csv')

# Check the dataset structure
str(df)
View(df)

# Check dimensions
nrow(df)
ncol(df)

# Look at first few rows
head(df)

# Identify missing values
colSums(is.na(df))


# DATA CLEANING AND PREPROCESSING

# CLEAN LABEL VARIABLE
# Label is our target variable where 0 = Normal traffic and 1 = Attack

# Count missing values before cleaning
sum(is.na(df$label))

# Check what values exist in label
table(df$label)

# Remove underscore and question mark from label
df$label = gsub("_", "", df$label)
df$label = gsub("\\?", "", df$label)

# Convert to numeric, this changes string "NA" into real NA
df$label = as.numeric(df$label)

# Fill missing labels using attack_cat column
# If attack_cat says "Normal" then label should be 0
df$label[which((is.na(df$label)) & (df$attack_cat == "Normal") & !is.na(df$attack_cat))] = 0
# If attack_cat says anything else then label should be 1
df$label[which((is.na(df$label)) & (!df$attack_cat == "Normal") & !is.na(df$attack_cat))] = 1

# Check how many labels still missing after recovery
sum(is.na(df$label))

# Remove rows where can't determine the label (both attack_cat and label are NA)
df = df[!(is.na(df$label) & is.na(df$attack_cat)), ]

# Confirm label now only has 0 and 1
table(df$label)

# CLEAN DUR VARIABLE
# dur represents the duration of network connection in seconds

# Check data type
class(df$dur)

# Count how many values have special characters
sum(grepl("[?_]", df$dur))

# Remove underscore and question mark
df$dur = gsub("_", "", df$dur)
df$dur = gsub("\\?", "", df$dur)

# Convert to numeric
df$dur = as.numeric(df$dur)

# Count missing values after conversion
sum(is.na(df$dur))

# CLEAN SBYTES VARIABLE
# sbytes is the number of bytes from source to destination

# Check data type
class(df$sbytes)

# Count how many values have special characters
sum(grepl("[?_]", df$sbytes))

# Remove underscore and question mark
df$sbytes = gsub("_", "", df$sbytes)
df$sbytes = gsub("\\?", "", df$sbytes)

# Convert to numeric
df$sbytes = as.numeric(df$sbytes)

# Count missing values after conversion
sum(is.na(df$sbytes))

# CLEAN SPKTS VARIABLE
# spkts is the number of packets from source to destination

# Remove special characters
df$spkts = gsub("_", "", df$spkts)
df$spkts = gsub("\\?", "", df$spkts)

# Convert to numeric
df$spkts = as.numeric(df$spkts)

# Count missing values
sum(is.na(df$spkts))

# CLEAN DBYTES VARIABLE
# dbytes is the number of bytes from destination to source

# Remove special characters
df$dbytes = gsub("_", "", df$dbytes)
df$dbytes = gsub("\\?", "", df$dbytes)

# Convert to numeric
df$dbytes = as.numeric(df$dbytes)

# Count missing values
sum(is.na(df$dbytes))

# CLEAN DPKTS VARIABLE
# dpkts is the number of packets from destination to source

# Remove special characters
df$dpkts = gsub("_", "", df$dpkts)
df$dpkts = gsub("\\?", "", df$dpkts)

# Convert to numeric
df$dpkts = as.numeric(df$dpkts)

# Count missing values
sum(is.na(df$dpkts))

# CLEAN STTL VARIABLE
# sttl is the source to destination time to live

# Remove special characters
df$sttl = gsub("_", "", df$sttl)
df$sttl = gsub("\\?", "", df$sttl)

# Convert to numeric
df$sttl = as.numeric(df$sttl)

# Count missing values
sum(is.na(df$sttl))

# CLEAN DTTL VARIABLE
# dttl is the destination to source time to live

# Remove special characters
df$dttl = gsub("_", "", df$dttl)
df$dttl = gsub("\\?", "", df$dttl)

# Convert to numeric
df$dttl = as.numeric(df$dttl)

# Count missing values
sum(is.na(df$dttl))

# CLEAN ATTACK_CAT VARIABLE
# attack_cat specifies the type of attack

# Check current state
print(unique(df$attack_cat))

# Total NAs
sum(is.na(df$attack_cat))

# Cross-check with label
sum(is.na(df$attack_cat) & df$label == 0)
sum(is.na(df$attack_cat) & df$label == 1)

# Replace NA with "Normal" for label = 0
df$attack_cat[is.na(df$attack_cat) & df$label == 0] = "Normal"

# Count how many rows will be removed (label = 1 but attack_cat is NA)
rows_to_remove = sum(is.na(df$attack_cat) & df$label == 1)
rows_to_remove

# Remove those rows since can't determine attack type
df = df[!is.na(df$attack_cat), ]

# Convert to factor
df$attack_cat = as.factor(df$attack_cat)
class(df$attack_cat)

# HANDLE MISSING VALUES USING GROUP-BASED MEDIAN IMPUTATION

# Calculate median for Normal traffic (label = 0)
median_dur_normal = median(df$dur[df$label == 0], na.rm = TRUE)
median_sbytes_normal = median(df$sbytes[df$label == 0], na.rm = TRUE)
median_spkts_normal = median(df$spkts[df$label == 0], na.rm = TRUE)
median_dbytes_normal = median(df$dbytes[df$label == 0], na.rm = TRUE)
median_dpkts_normal = median(df$dpkts[df$label == 0], na.rm = TRUE)
median_sttl_normal = median(df$sttl[df$label == 0], na.rm = TRUE)
median_dttl_normal = median(df$dttl[df$label == 0], na.rm = TRUE)

# Calculate median for Attack traffic (label = 1)
median_dur_attack = median(df$dur[df$label == 1], na.rm = TRUE)
median_sbytes_attack = median(df$sbytes[df$label == 1], na.rm = TRUE)
median_spkts_attack = median(df$spkts[df$label == 1], na.rm = TRUE)
median_dbytes_attack = median(df$dbytes[df$label == 1], na.rm = TRUE)
median_dpkts_attack = median(df$dpkts[df$label == 1], na.rm = TRUE)
median_sttl_attack = median(df$sttl[df$label == 1], na.rm = TRUE)
median_dttl_attack = median(df$dttl[df$label == 1], na.rm = TRUE)

# Replace missing values for dur based on their label
df$dur[is.na(df$dur) & df$label == 0] = median_dur_normal
df$dur[is.na(df$dur) & df$label == 1] = median_dur_attack

# Replace missing values for sbytes based on their label
df$sbytes[is.na(df$sbytes) & df$label == 0] = median_sbytes_normal
df$sbytes[is.na(df$sbytes) & df$label == 1] = median_sbytes_attack

# Replace missing values for spkts based on their label
df$spkts[is.na(df$spkts) & df$label == 0] = median_spkts_normal
df$spkts[is.na(df$spkts) & df$label == 1] = median_spkts_attack

# Replace missing values for dbytes based on their label
df$dbytes[is.na(df$dbytes) & df$label == 0] = median_dbytes_normal
df$dbytes[is.na(df$dbytes) & df$label == 1] = median_dbytes_attack

# Replace missing values for dpkts based on their label
df$dpkts[is.na(df$dpkts) & df$label == 0] = median_dpkts_normal
df$dpkts[is.na(df$dpkts) & df$label == 1] = median_dpkts_attack

# Replace missing values for sttl based on their label
df$sttl[is.na(df$sttl) & df$label == 0] = median_sttl_normal
df$sttl[is.na(df$sttl) & df$label == 1] = median_sttl_attack

# Replace missing values for dttl based on their label
df$dttl[is.na(df$dttl) & df$label == 0] = median_dttl_normal
df$dttl[is.na(df$dttl) & df$label == 1] = median_dttl_attack


# DATA VALIDATION

# Verify no missing values remain in our variables
sum(is.na(df$dur))
sum(is.na(df$sbytes))
sum(is.na(df$spkts))
sum(is.na(df$dbytes))
sum(is.na(df$dpkts))
sum(is.na(df$sttl))
sum(is.na(df$dttl))
sum(is.na(df$label))
sum(is.na(df$attack_cat))

# Confirm label only contains 0 and 1
table(df$label)

# Verify all columns are numeric type
class(df$dur)
class(df$sbytes)
class(df$spkts)
class(df$dbytes)
class(df$dpkts)
class(df$sttl)
class(df$dttl)
class(df$label)

# Check final dataset size after cleaning
nrow(df)

# Review summary statistics after cleaning
summary(df$dur)
summary(df$sbytes)
summary(df$spkts)
summary(df$dbytes)
summary(df$dpkts)
summary(df$sttl)
summary(df$dttl)

# Check for negative values (duration and bytes cannot be negative)
sum(df$dur < 0)
sum(df$sbytes < 0)
sum(df$dbytes < 0)

# Check for zero values
sum(df$dur == 0)
sum(df$sbytes == 0)

# Data cleaning and validation complete



##########################################################################
# 1. VISUAL EXPLORATORY ANALYSIS
##########################################################################

# Research Question: Can visual patterns reveal differences in dur
# and sbytes between Normal and Attack traffic?

# Graph 1: Boxplot for dur
ggplot(df, aes(x = factor(label), y = dur, fill = factor(label))) +
  geom_boxplot() +
  labs(title = "Connection Duration by Traffic Type",
       x = "Traffic Type",
       y = "Duration (seconds)",
       fill = "Label") +
  theme_minimal()

# Graph 2: Boxplot for sbytes
ggplot(df, aes(x = factor(label), y = sbytes, fill = factor(label))) +
  geom_boxplot() +
  labs(title = "Source Bytes by Traffic Type",
       x = "Traffic Type",
       y = "Source Bytes",
       fill = "Label") +
  theme_minimal()

# Graph 3: Scatter plot showing relationship
ggplot(df, aes(x = dur, y = sbytes, color = factor(label))) +
  geom_point(alpha = 0.3) +
  geom_smooth() +
  labs(title = "Relationship Between Duration and Source Bytes",
       x = "Duration (seconds)",
       y = "Source Bytes",
       color = "Traffic Type") +
  theme_minimal()

##########################################################################
# 2. STATISTICAL HYPOTHESIS TESTING
##########################################################################

# Research Question: Are the observed differences in connection duration and 
# source bytes between Normal and Attack traffic statistically significant?


# Test if dur is different between Normal and Attack
wilcox.test(dur ~ label, data = df)

# Test if sbytes is different between Normal and Attack
wilcox.test(sbytes ~ label, data = df)

# Check correlation between dur and sbytes
cor.test(df$dur, df$sbytes, method = "spearman")

# Check correlation between dur and label
cor.test(df$dur, df$label, method = "spearman")

# Check correlation between sbytes and label
cor.test(df$sbytes, df$label, method = "spearman")

##########################################################################
# 3. PREDICTIVE MODELING ANALYSIS
##########################################################################

# Research Question: Can connection duration, source bytes, and source packet 
# count accurately predict network attacks?

# Set seed for reproducibility
set.seed(123)

# Create train/test split (70% train, 30% test)
train_index = sample(1:nrow(df), 0.7 * nrow(df))
train_data = df[train_index, ]
test_data = df[-train_index, ]

# Check split
nrow(train_data)
nrow(test_data)
table(train_data$label)
table(test_data$label)

# Build random forest model for binary classification
model_rf = randomForest(factor(label) ~ dur + sbytes + spkts,
                        data = train_data,
                        ntree = 500,
                        importance = TRUE)

# View model
model_rf

# Make predictions on test data
pred_rf = predict(model_rf, test_data)

# Evaluate random forest
confusionMatrix(pred_rf,
                factor(test_data$label),
                positive = "1")

# Variable importance
importance(model_rf)
varImpPlot(model_rf)

# Random Forest Accuracy
mean(pred_rf == test_data$label)

##########################################################################
# 4. MULTI-CLASS CLASSIFICATION
##########################################################################

# Predicting Attack Types using attack_cat
# Using 7 variables: dur, sbytes, spkts, dbytes, dpkts, sttl, dttl

# Create train/test split (70% train, 30% test)
train_index = sample(1:nrow(df), 0.7 * nrow(df))
train_data = df[train_index, ]
test_data = df[-train_index, ]

# Check attack categories distribution
table(train_data$attack_cat)
table(test_data$attack_cat)

# Build Random Forest for attack type classification
model_multiclass = randomForest(attack_cat ~ dur + sbytes + spkts +
                                  dbytes + dpkts + sttl + dttl,
                                data = train_data,
                                ntree = 500,
                                importance = TRUE)

model_multiclass

# Predict attack types on test data
pred_multiclass = predict(model_multiclass, test_data)

# Confusion matrix
confusion_multiclass = confusionMatrix(pred_multiclass,
                                       test_data$attack_cat)
confusion_multiclass

# Display accuracy
mean(pred_multiclass == test_data$attack_cat)

# Variable importance
importance(model_multiclass)
varImpPlot(model_multiclass, main = "Variable Importance - Attack Type Classification")

# Per-class statistics
confusion_multiclass$byClass

# Sensitivity (detection rate) for each attack type
confusion_multiclass$byClass[, "Sensitivity"]
