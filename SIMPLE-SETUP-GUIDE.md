# M365 Brain Crawl - Simple Setup Guide for Business Users

## What This System Does (In Plain English)

The M365 Brain Crawl system automatically collects information from your Microsoft 365 environment - like Teams conversations, SharePoint documents, user profiles, and more - so you can analyze and understand your organization's data patterns.

Think of it as a smart assistant that reads through all your Microsoft 365 content and organizes it for you to analyze, search, and gain insights from.

## What You'll Get After Setup

After following this guide, you'll have:
- ✅ A cloud-based system running in Microsoft Azure
- ✅ Ability to collect data from any Microsoft 365 organization
- ✅ API endpoints to retrieve organized data
- ✅ Admin tools to manage the system
- ✅ Security controls to protect sensitive information

## Before You Start - Checklist

### What You Need:
- [ ] **Microsoft Azure Account** - You need access to create resources (usually requires admin rights)
- [ ] **Microsoft 365 Admin Rights** - To approve data access permissions
- [ ] **10-15 minutes** - The setup process is mostly automated
- [ ] **Basic computer skills** - Copy, paste, and follow instructions

### What You'll Spend:
- **Azure costs**: Approximately $5-20/month depending on usage
- **Setup time**: 10-15 minutes of your time
- **Technical knowledge**: None required - this guide handles everything

## Step-by-Step Setup Instructions

### Step 1: Open Azure Cloud Shell
1. Go to [portal.azure.com](https://portal.azure.com) in your web browser
2. Sign in with your Azure account
3. Look for the shell icon (>_) in the top menu bar
4. Click it to open Azure Cloud Shell
5. Choose **Bash** when prompted (not PowerShell)

*Screenshot reference: Look for the terminal/shell icon in the blue top bar*

### Step 2: Run the One-Command Setup
1. In the black terminal window that opens, type this command:
   ```bash
   curl -s https://raw.githubusercontent.com/your-repo/M365Crawl/main/one-click-deploy.sh | bash
   ```

2. **OR** if you prefer to see the script first (recommended):
   ```bash
   # Download the setup script
   curl -o setup-m365-brain.sh https://raw.githubusercontent.com/your-repo/M365Crawl/main/one-click-deploy.sh
   
   # Make it executable and run it
   chmod +x setup-m365-brain.sh
   ./setup-m365-brain.sh
   ```

### Step 3: Wait and Watch
The script will automatically:
- ✅ Check that everything is ready
- ✅ Create all the Azure resources you need
- ✅ Set up the Microsoft 365 connection
- ✅ Test that everything works
- ✅ Give you a summary of what was created

**This takes about 5-10 minutes. You'll see progress messages telling you what's happening.**

### Step 4: Approve Microsoft 365 Access
After the script finishes, it will show you a special web link. You need to:

1. **Copy the "Admin Consent URL"** that appears at the end
2. **Open it in your web browser**
3. **Sign in as a Microsoft 365 admin**
4. **Click "Accept"** to allow the system to read your M365 data

*This step gives the system permission to access your Microsoft 365 information*

### Step 5: Test That Everything Works
The setup script automatically tests your system, but you can verify it's working:

1. **Health Check**: Visit the health URL shown in the results
2. **Data Test**: The system will try to connect to Microsoft 365
3. **Admin Panel**: You'll get access URLs for managing the system

## What Happens Next

### Immediate Results:
- Your system is live and running in Microsoft Azure
- It can connect to Microsoft 365 and collect data
- You have admin tools to control what it does
- All security protections are active

### What You Can Do Now:
1. **Test Data Collection**: Try collecting data from your M365 tenant
2. **Set Up Additional Organizations**: Use the admin consent URL for other companies
3. **Monitor Usage**: Check Azure portal for system health and costs
4. **Manage Permissions**: Control what data the system can access

## Important Security Information

### What the System Can Access:
- Microsoft Teams messages and channels
- SharePoint sites and documents
- User profiles and group memberships
- Calendar information (if you enable it)

### What It Cannot Do:
- Modify or delete your data
- Access personal emails
- Change user permissions
- Operate without admin approval

### Security Features:
- All data transfers use encryption
- No data is stored permanently unless you configure it
- You control which organizations can be accessed
- All access requires admin approval

## Cost Information

### Azure Resources Created:
- **Function App**: ~$5-15/month (handles the data processing)
- **Storage Account**: ~$1-5/month (stores temporary files)
- **Resource Group**: Free (organizes everything)

### Cost Optimization Tips:
- The system only costs money when actively running
- You can pause it when not needed
- Costs scale with usage - more data = higher costs
- Monitor usage in Azure portal to track spending

## Troubleshooting Common Issues

### "I can't access Azure Portal"
**Problem**: Your account doesn't have Azure access
**Solution**: Contact your IT admin to get Azure contributor access

### "The script says I'm not logged in"
**Problem**: Azure Cloud Shell lost connection
**Solution**: Close and reopen Cloud Shell, then try again

### "Microsoft 365 admin consent failed"
**Problem**: You don't have M365 admin rights
**Solution**: Ask your Microsoft 365 admin to click the consent URL

### "The health check URL doesn't work"
**Problem**: The system might still be starting up
**Solution**: Wait 2-3 minutes and try again

### "I'm getting cost alerts"
**Problem**: Higher than expected Azure charges
**Solution**: Check the Azure portal usage dashboard and consider pausing the system

## Getting Help

### If Something Goes Wrong:
1. **Check the error message** - it usually tells you what's wrong
2. **Look at this troubleshooting section**
3. **Try running the setup script again** - it's safe to run multiple times
4. **Contact your IT support** with the error message

### For Questions About:
- **Azure costs**: Check the Azure pricing calculator
- **Microsoft 365 permissions**: Contact your M365 admin
- **Data privacy**: Review the security information above
- **System performance**: Check Azure monitoring tools

### Support Resources:
- Azure documentation: [docs.microsoft.com/azure](https://docs.microsoft.com/azure)
- Microsoft 365 admin center: [admin.microsoft.com](https://admin.microsoft.com)
- This system's documentation: See the README.md file

## Success! What You've Accomplished

After completing this setup, you have:

✅ **A Professional Data Collection System** running in the cloud
✅ **Secure Access** to Microsoft 365 data with proper permissions  
✅ **Automated Processing** that can handle large amounts of information
✅ **Cost-Effective Solution** that only charges for what you use
✅ **Enterprise Security** with encryption and access controls
✅ **Scalable Platform** that can grow with your needs

**Congratulations! You've successfully set up an enterprise-grade M365 data collection system.**

---

## Quick Reference

### Important URLs (you'll get these after setup):
- **System Health**: `https://your-system.azurewebsites.net/api/health`
- **Admin Consent**: `https://login.microsoftonline.com/...` (generated by script)
- **Azure Portal**: [portal.azure.com](https://portal.azure.com)

### Key Commands:
- **Check system status**: Visit the health URL
- **View Azure resources**: Go to Azure Portal > Resource Groups > "m365-agent-rg"
- **Monitor costs**: Azure Portal > Cost Management

### Next Steps:
1. Test data collection with your first organization
2. Set up monitoring and alerts
3. Configure additional Microsoft 365 tenants
4. Explore the data analysis capabilities

*This guide was designed for business users who want results without technical complexity.*