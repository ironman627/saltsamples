# Setting Up Approval for Salt State Converter

## Overview
The Salt State Converter workflow can automatically convert Salt state files to best practices. To prevent unwanted automatic conversions, an approval mechanism has been configured that requires an admin to review and approve conversions before they run.

## How It Works

1. **Analyze Phase**: When you push `.sls` files or manually trigger the workflow, it first analyzes your Salt state files
2. **Approval Required**: If conversions are needed, the workflow pauses and waits for admin approval
3. **Notification**: Designated reviewers receive a notification in GitHub
4. **Review & Approve**: Admin reviews the analysis and approves/rejects the conversion
5. **Conversion**: Only after approval does the conversion run and create a PR

## Required Setup Steps

### Step 1: Create the Environment

1. Navigate to your repository on GitHub
2. Click **Settings** (top menu bar)
3. In the left sidebar, click **Environments**
4. Click **New environment** button
5. Enter the name: `salt-conversion-approval`
6. Click **Configure environment**

### Step 2: Add Required Reviewers

1. In the environment configuration page, under **Deployment protection rules**:
   - Check ✅ **Required reviewers**
   - Click in the **Search for people or teams** box
   - Add GitHub usernames who can approve (e.g., `ironman627`)
   - You can add multiple reviewers
   - At least one reviewer must approve before the workflow continues

### Step 3: (Optional) Configure Additional Settings

- **Wait timer**: Set a minimum wait time before approval (prevents immediate auto-approval)
- **Deployment branches**: Limit which branches can trigger this environment (default: all branches)
- **Environment secrets**: Add any environment-specific secrets if needed

### Step 4: Save Configuration

Click **Save protection rules** at the bottom of the page.

## Testing the Setup

1. **Trigger the workflow manually**:
   - Go to **Actions** tab
   - Click **Salt State Converter** workflow
   - Click **Run workflow**
   - Select action: **convert**
   - Click **Run workflow**

2. **Check for approval request**:
   - The `analyze` job should complete
   - The `convert` job should show "Waiting" status
   - You (or designated reviewers) should see a notification
   - Go to the workflow run and click **Review deployments** button

3. **Approve or Reject**:
   - Review the analysis results
   - Check the number of files to be converted
   - Click **Approve and deploy** or **Reject**
   - If approved, the conversion will proceed

## Troubleshooting

### "Skipped" Status Instead of "Waiting"

If the convert job shows "Skipped" instead of "Waiting for approval":

1. **Environment not created**: Make sure you created the `salt-conversion-approval` environment exactly as named
2. **No files need conversion**: Check the analyze job output - if no files need conversion, convert job will skip
3. **Condition not met**: Verify you selected action "convert" when manually triggering

### Not Receiving Notifications

1. **Check GitHub notification settings**:
   - Go to **Settings** → **Notifications** (in your personal GitHub settings)
   - Ensure "Actions" notifications are enabled
   - Check both web and email notification preferences

2. **Verify you're added as a reviewer**:
   - Go to repository **Settings** → **Environments** → **salt-conversion-approval**
   - Confirm your username is listed under Required reviewers

3. **Watch the repository**:
   - Go to the repository main page
   - Click **Watch** → **All Activity**

## Workflow Triggers

The workflow can be triggered three ways:

### 1. Manual (workflow_dispatch)
- Go to Actions → Salt State Converter → Run workflow
- Choose action: "analyze" or "convert"
- Convert action will require approval

### 2. Push to main/master
- Automatically runs when `.sls` or `.jinja` files are pushed
- If files need conversion, waits for approval before converting

### 3. Pull Request
- Runs analyze only (no conversion)
- Posts analysis results as a comment on the PR
- Does not require approval (read-only)

## Security Considerations

- Only trusted admins should be added as required reviewers
- Reviewers should always check the analysis results before approving
- The approval requirement prevents malicious or accidental mass conversions
- Each conversion creates a new branch and PR for additional review before merging

## Further Information

For questions or issues with the approval workflow, contact your repository administrators.
