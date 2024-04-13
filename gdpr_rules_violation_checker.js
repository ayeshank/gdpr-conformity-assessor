const bucketList = document.getElementById("bucketList");
const details = document.getElementById("details");
const gdprRulesList = document.getElementById("gdprRulesList");
const mycontainer = document.getElementById("mycontainer");

// Store GDPR violations grouped by the rule they violate
const violationsByRule = new Map();

// Define GDPR rules and their violations
const gdprRules = {
  rule1: {
    name: "GDPR Rule: Data Security Encryption Policy.",
    severity: "High",
    violations: ["Missing encryption settings"],
    articles: ["Article 32: Security of processing"],
  },
  rule2: {
    name: "GDPR Rule: Data Access Control Policy",
    severity: "High",
    violations: [
      "BlockPublicAcls not enabled",
      "IgnorePublicAcls not enabled",
      "BlockPublicPolicy not enabled",
      "RestrictPublicBuckets is not enabled",
      "Blob public access is enabled",
      "Last accessed on is not set",
      "Public Network Access is enabled",
      "Grant to global/AllUsers found, which may lead to unauthorized access.",
      "Grant to global/AuthenticatedUsers found, which may lead to unauthorized access.",
    ],
    articles: [
      "Article 5: Principles relating to processing of personal data",
      "Article 6: Lawfulness of processing",
      "Article 25: Data protection by design and by default",
      "Article 32: Security of processing",
      "Article 35: Data protection impact assessment",
    ],
  },
  rule3: {
    name: "GDPR Rule: Data Version Control Policy",
    severity: "High",
    violations: ["Versioning not enabled"],
    articles: [
      "Article 5: Principles relating to processing of personal data",
      "Article 32: Security of processing",
    ],
  },
  rule4: {
    name: "GDPR Rule: Data Labeling Policy",
    severity: "Medium",
    violations: ["Missing tagging"],
    articles: [
      "Article 5: Principles relating to processing of personal data",
      "Article 25: Data protection by design and by default",
    ],
  },
  rule5: {
    name: "GDPR Rule: Data Logging Policy",
    severity: "Medium",
    violations: ["Logging not set"],
    articles: [
      "Article 32: Security of processing",
      "Article 5: Principles relating to processing of personal data",
    ],
  },
  rule6: {
    name: "GDPR Rule: Data Transfer Acceleration Policy",
    severity: "Medium",
    violations: ["Transfer Acceleration not enabled"],
    articles: [
      "Article 32: Security of processing",
      "Article 5: Principles relating to processing of personal data",
    ],
  },
  rule7: {
    name: "GDPR Rule: Data Version Control with MFA Policy",
    severity: "Low",
    violations: ["Versioning MFA not configured"],
    articles: [
      "Article 5: Principles relating to processing of personal data",
      "Article 32: Security of processing",
    ],
  },
  rule8: {
    name: "GDPR Rule: Data Retention and Immutability Policy",
    severity: "Low",
    violations: ["Object Lock Configuration not enabled"],
    articles: [
      "Article 5: Principles relating to processing of personal data",
      "Article 25: Data protection by design and by default",
      "Article 32: Security of processing",
    ],
  },
  rule9: {
    name: "GDPR Rule: Data Lifecycle Management Policy",
    severity: "Low",
    violations: ["Lifecycle management not configured"],
    articles: [
      "Article 5: Principles relating to processing of personal data",
      "Article 25: Data protection by design and by default",
      "Article 32: Security of processing",
    ],
  },
  rule10: {
    name: 'GDPR Rule: Right to Erasure ("Right to be Forgotten")',
    severity: "High",
    article: "Article 17: Right to erasure (‘right to be forgotten’)",
    violations: [
      "Remaining Retention Days not defined",
      "Deleted flag or Deleted Time not set",
    ],
  },
  rule11: {
    name: "GDPR Rule: Data Immutability Policy",
    violations: ["Immutability Policy Mode is not configured"],
    article: "Article 44: General principle for transfers",
    severity: "High",
  },
};

var getAzureData;
var getAWSData;

function checkGDPRViolations() {
  // Check if cached data exists for both AWS and Azure
  // const cachedAWSData = localStorage.getItem('aws_bucket_details');
  // const cacheTimestampAWS = localStorage.getItem('aws_bucket_details_timestamp');
  // const cachedAzureData = localStorage.getItem('azure_bucket_details');
  // const cacheTimestampAzure = localStorage.getItem('azure_bucket_details_timestamp');

  // if (cachedAWSData && cacheTimestampAWS && cachedAzureData && cacheTimestampAzure) {
  //     // Calculate the time difference for both AWS and Azure data
  //     const currentTime = new Date().getTime();
  //     const cacheTimeAWS = new Date(cacheTimestampAWS).getTime();
  //     const cacheTimeAzure = new Date(cacheTimestampAzure).getTime();
  //     const hoursSinceCacheAWS = (currentTime - cacheTimeAWS) / 1000 / 60 / 60;
  //     const hoursSinceCacheAzure = (currentTime - cacheTimeAzure) / 1000 / 60 / 60;

  //     if (hoursSinceCacheAWS < 4 && hoursSinceCacheAzure < 4) {
  //         // If data for both AWS and Azure is less than 4 hours old, use the cached data
  //         const awsData = JSON.parse(cachedAWSData);
  //         const azureData = JSON.parse(cachedAzureData);
  //         displayBucketList(awsData, azureData);
  //         return;
  //     }
  // }

  // If cached data is older than 4 hours or doesn't exist, fetch fresh data for both AWS and Azure
  fetchFreshData();
}

function fetchFreshData() {
  Promise.all([
    fetch("./aws_bucket_details.json").then((response) => response.json()),
    fetch("./azure_bucket_details.json").then((response) => response.json()),
    //     fetch(
    //       "https://asset-config-storage.s3.us-west-2.amazonaws.com/all-bucket-details.json"
    //     ).then((response) => response.json()),
    //     fetch(
    //       "https://cloudcomputingiba.blob.core.windows.net/cloud-computing-test/all-storage-account-details.json?sp=r&st=2023-11-11T14:01:57Z&se=2023-11-29T22:01:57Z&spr=https&sv=2022-11-02&sr=b&sig=FlCyZDpg2xGptC64y7EbyKikdJW6pdTO3uhRdE%2B994Y%3D"
    //     ).then((response) => response.json()),
  ])
    .then(([awsData, azureData]) => {
      // Cache the fetched data in localStorage
      localStorage.setItem("aws_bucket_details", JSON.stringify(awsData));
      localStorage.setItem(
        "azure_bucket_details",
        JSON.stringify(azureData.StorageAccountDetails)
      );

      // Update the timestamp of the cached data for both AWS and Azure
      const currentTime = new Date().toISOString();
      localStorage.setItem("aws_bucket_details_timestamp", currentTime);
      localStorage.setItem("azure_bucket_details_timestamp", currentTime);

      displayBucketList(awsData, azureData.StorageAccountDetails);
    })
    .catch((error) => console.error("Error fetching data:", error));
}

function getSeverity(violation) {
  if (violation["severity"].includes("High")) {
    return "High";
  } else if (violation["severity"].includes("Medium")) {
    return "Medium";
  } else if (violation["severity"].includes("Low")) {
    return "Low";
  } else {
    return "High";
  }
}

// Function to create a dropdown for GDPR rules and their violations
function createGDPRDropdown(violationsForBucket) {
  const gdprRulesList = document.getElementById("gdprRulesList");

  // Clear previous content
  gdprRulesList.innerHTML = "";

  violationsForBucket.forEach(({ rule, violations }) => {
    const { name } = gdprRules[rule];

    // Create list item
    const ruleItem = document.createElement("li");
    ruleItem.classList.add("gdpr-rules-li");

    // Create a container for rule name and dropdown icon
    const ruleContainer = document.createElement("div");
    ruleContainer.classList.add("rule-container");

    // Rule name
    const ruleName = document.createElement("div");
    ruleName.innerText = name;

    // Create a dropdown icon element
    const dropDownIcon = document.createElement("img");
    dropDownIcon.classList.add("dropdown-icon");
    dropDownIcon.src = "down-arrow.png";

    // Append the rule name and dropdown icon to the container
    ruleContainer.appendChild(ruleName);
    ruleContainer.appendChild(dropDownIcon);

    // Append the container to the list item
    ruleItem.appendChild(ruleContainer);

    // Create a list for violations under this rule
    const violationsList = document.createElement("ul");
    violationsList.classList.add("gdpr-rules-ul-2");
    violationsList.style.display = "none"; // Initially hidden

    violations.forEach((violation) => {
      // Create a chip for severity
      const severityChip = document.createElement("div");
      severityChip.classList.add("severity-chip");

      const violationItem = document.createElement("li");
      violationItem.classList.add("gdpr-rules-li-2");

      // Create a warning icon element
      const warningIcon = document.createElement("img");
      warningIcon.classList.add("warning-icon");

      // Create a container for the violation text
      const violationTextContainer = document.createElement("div");
      violationTextContainer.classList.add("violation-text-container");
      // Set color based on severity
      switch (getSeverity(violation)) {
        case "High":
          violationTextContainer.style.color = "red";
          warningIcon.src = "warning.png";
          severityChip.style.backgroundColor = "red";
          break;
        case "Medium":
          violationTextContainer.style.color = "#E6960E";
          warningIcon.src = "warningOrange.png";
          severityChip.style.backgroundColor = "#E6960E";
          break;
        case "Low":
          violationTextContainer.style.color = "#85E21C";
          warningIcon.src = "warningYellow.png";
          severityChip.style.backgroundColor = "#85E21C";
          break;
        default:
          violationTextContainer.style.color = "red";
          wwarningIcon.src = "warning.png";
      }
      severityChip.innerText = violation["severity"] + " Severity";
      violationTextContainer.innerText = violation["rule"];

      // Append the warning icon and violation text container
      violationItem.appendChild(warningIcon);
      violationItem.appendChild(severityChip);
      violationItem.appendChild(violationTextContainer);
      violationsList.appendChild(violationItem);
    });

    ruleItem.addEventListener("click", () => {
      if (violationsList.style.display === "none") {
        violationsList.style.display = "block"; // Show violations
      } else {
        violationsList.style.display = "none"; // Hide violations
      }
    });

    ruleItem.appendChild(violationsList); // Attach violations list to the rule
    gdprRulesList.appendChild(ruleItem);
  });
}

function displayBucketList(awsData, azureData) {
  bucketList.innerHTML = "";
  console.log("displayBucketList: azureData: ", azureData);
  //commented for json data
  //   awsData.BucketDetails.forEach((AWSbucket) => {
  awsData.forEach((AWSbucket) => {
    const listItem = document.createElement("li");
    listItem.style.textAlign = "left";
    listItem.innerText = AWSbucket.BucketName;
    listItem.addEventListener("click", () =>
      displayBucketDetails(AWSbucket, "AWS", AWSbucket.BucketName, "")
    );
    bucketList.appendChild(listItem);
  });

  azureData.forEach((AzureS3) => {
    const listItem = document.createElement("li");
    listItem.style.textAlign = "left";
    listItem.innerText =
      AzureS3["StorageAccountName"] + " " + AzureS3["BlobName"];
    listItem.addEventListener("click", () =>
      displayBucketDetails(
        AzureS3,
        "Azure",
        AzureS3["StorageAccountName"],
        AzureS3["BlobName"]
      )
    );
    bucketList.appendChild(listItem);
  });
}

// The displayBucketDetails function to pass the correct violations to createGDPRDropdown
function displayBucketDetails(bucket, cloud, headerTitle, myBlobname) {
  details.innerHTML = "";
  mycontainer.style.alignItems = "flex-start";

  // Add header title
  const headerElement = document.createElement("div");
  headerElement.innerHTML = `<p>Bucket/Storage Name: ${headerTitle} ${myBlobname}</p>`;
  headerElement.classList.add("detail-header");
  details.appendChild(headerElement);

  if (cloud == "AWS") {
    var combinedViolations = checkAWSGDPRViolationsInBucket(bucket);
  } else if (cloud == "Azure") {
    var combinedViolations = checkAzureGDPRViolationsInBucket(bucket);
  }
  const violationsForBucket = Object.keys(gdprRules)
    .filter((rule) =>
      combinedViolations.some((violation) =>
        gdprRules[rule].violations.includes(violation["rule"])
      )
    )
    .map((rule) => ({
      rule,
      violations: combinedViolations.filter((violation) =>
        gdprRules[rule].violations.includes(violation["rule"])
      ),
    }));

  createGDPRDropdown(violationsForBucket);

  violationsByRule.clear();

  violationsForBucket.forEach(({ rule, violations }) => {
    violationsByRule.set(rule, violations);
  });

  if (violationsForBucket.length === 0) {
    // Create a div for the message and append it to details
    // const messageElement = document.createElement('div');
    // messageElement.innerHTML = 'No GDPR rule violations for this bucket.';
    // details.appendChild(messageElement);

    const messageElement = document.createElement("div");
    const imageElement = document.createElement("img");
    imageElement.src = "compliant2.png"; // Replace with the actual path to your image
    imageElement.alt = "Compliant";
    imageElement.style.display = "block"; // Make it a block element to center-align
    imageElement.style.margin = "30px auto"; // Center-align the image
    imageElement.style.width = "90px";
    imageElement.style.height = "90px";
    messageElement.appendChild(imageElement);
    messageElement.innerHTML +=
      "Congratulations! Your Bucket is GDPR Compliant";
    messageElement.innerHTML +=
      "<br> No GDPR Rule Violations For This Bucket Found.";
    messageElement.style.color = "#00C8C8";
    messageElement.style.fontWeight = "bold";
    details.appendChild(messageElement);
  }
}

// Function to check GDPR violations for a bucket based on your defined rules
function checkAWSGDPRViolationsInBucket(bucket) {
  const violations = [];

  // Rule 1: Encryption Settings
  if (
    !bucket.Encryption ||
    !bucket.Encryption.Rules ||
    bucket.Encryption.Rules.length === 0
  ) {
    violations.push({ rule: "Missing encryption settings", severity: "High" });
  }

  // Rule 2: Public Access
  if (bucket.PublicAccess) {
    if (!bucket.PublicAccess.BlockPublicAcls) {
      violations.push({
        rule: "BlockPublicAcls not enabled",
        severity: "High",
      });
    }
    if (!bucket.PublicAccess.IgnorePublicAcls) {
      violations.push({
        rule: "IgnorePublicAcls not enabled",
        severity: "High",
      });
    }
    if (!bucket.PublicAccess.BlockPublicPolicy) {
      violations.push({
        rule: "BlockPublicPolicy not enabled",
        severity: "High",
      });
    }
    if (bucket.PublicAccess.RestrictPublicBuckets == false) {
      violations.push({
        rule: "RestrictPublicBuckets is not enabled",
        severity: "High",
      });
    }
  }

  // Rule 3: Versioning
  if (bucket.Versioning === null) {
    violations.push({ rule: "Versioning not enabled", severity: "High" });
  }

  // Rule 4: Tagging
  if (!bucket.Tagging || bucket.Tagging.length === 0) {
    violations.push({ rule: "Missing tagging", severity: "Medium" });
  }

  // Rule 5: Logging
  if (!bucket.Logging || bucket.Logging.length === 0) {
    violations.push({ rule: "Logging not set", severity: "Medium" });
  }

  // Rule 6: TransferAcceleration
  if (
    !bucket.TransferAcceleration ||
    bucket.TransferAcceleration == null ||
    bucket.TransferAcceleration == "Disabled"
  ) {
    violations.push({
      rule: "Transfer Acceleration not enabled",
      severity: "Medium",
    });
  }

  // Rule 7: VersioningMFA
  if (
    !bucket.VersioningMFA ||
    bucket.VersioningMFA == null ||
    bucket.VersioningMFA == "Disabled"
  ) {
    violations.push({ rule: "Versioning MFA not configured", severity: "Low" });
  }

  // Rule 8: ObjectLockConfig
  if (
    !bucket.ObjectLockConfig ||
    bucket.ObjectLockConfig == null ||
    bucket.ObjectLockConfig == "Disabled"
  ) {
    violations.push({
      rule: "Object Lock Configuration not enabled",
      severity: "Low",
    });
  }

  // Rule 9: Lifecycle
  if (
    !bucket.Lifecycle ||
    bucket.Lifecycle == null ||
    bucket.Lifecycle == "Disabled"
  ) {
    violations.push({
      rule: "Lifecycle management not configured",
      severity: "Low",
    });
  }

  if (bucket.Grants && bucket.Grants.length > 0) {
    bucket.Grants.forEach((item, index) => {
      if (
        item.Permission == "WRITE_ACP" ||
        item.Permission == "WRITE" ||
        item.Permission == "READ_ACP" ||
        item.Permission == "FULL_CONTROL"
      ) {
        if (
          item.Grantee["URI"] &&
          item.Grantee["URI"].endsWith("global/AllUsers")
        ) {
          violations.push({
            rule: "Grant to global/AllUsers found, which may lead to unauthorized access.",
            severity: "High",
          });
        }
        if (
          item.Grantee["URI"] &&
          item.Grantee["URI"].endsWith("global/AuthenticatedUsers")
        ) {
          violations.push({
            rule: "Grant to global/AuthenticatedUsers found, which may lead to unauthorized access.",
            severity: "High",
          });
        }
      }
    });
  }

  return violations;
}

function checkAzureGDPRViolationsInBucket(AzureS3) {
  const violations = [];

  // Rule 1: Encryption Settings
  if (
    AzureS3["EncryptionSettings"] !== true ||
    AzureS3["ServerEncrypted"] !== true
  ) {
    violations.push({ rule: "Missing encryption settings", severity: "High" });
  }

  // Rule 2: Public Access
  if (AzureS3["AllowBlobPublicAccess"] !== false) {
    violations.push({
      rule: "Blob public access is enabled",
      severity: "High",
    });
  }
  if (AzureS3["PublicNetworkAccess"] == "Enabled") {
    violations.push({
      rule: "Public network access is enabled",
      severity: "High",
    });
  }
  if (AzureS3["LastAccessedOn"] == false) {
    violations.push({ rule: "Last accessed on is not set", severity: "High" });
  }

  // Rule 4: versioning
  if (
    AzureS3["VersionId"] == null ||
    AzureS3["BlobType"] == null ||
    AzureS3["BlobTier"] == null
  ) {
    violations.push({ rule: "Versioning not enabled", severity: "High" });
  }

  // Rule 5: LoggingEnabled
  if (AzureS3["LoggingEnabled"] == "no" || AzureS3["LoggingEnabled"] == null) {
    violations.push({ rule: "Logging not set", severity: "Medium" });
  }

  //Rule 10 Erasure
  if (AzureS3["RemainingRetentionDays"] == null) {
    violations.push({
      rule: "Remaining Retention Days not defined",
      severity: "High",
    });
  }

  if (AzureS3["Deleted"] == false || AzureS3["DeletedTime"] == null) {
    violations.push({
      rule: "Deleted flag or Deleted Time not set",
      severity: "High",
    });
  }

  if (AzureS3["BlobACL"] == "NotFound") {
    violations.push({ rule: "BlockPublicAcls not enabled", severity: "High" });
  }

  if (AzureS3["ImmutabilityPolicyMode"] == null) {
    violations.push({
      rule: "Immutability Policy Mode is not configured",
      severity: "High",
    });
  }

  return violations;
}
