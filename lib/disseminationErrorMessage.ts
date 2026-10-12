/** Allowlisted admin guidance; unknown upstream errors are never displayed verbatim. */
export function disseminationErrorMessage(error: string): string {
  switch (error) {
    case 'packet_evidence_size_unsupported':
      return 'The complete evidence package could not be prepared because attachment sizes are invalid or exceed the supported limit. Contact your administrator; no attachment will be silently omitted.';
    case 'narrative_review_required':
      return 'Complete Narrative Review before generating or sending a link. Choose “Mark reviewed — no redaction needed”, or run AI Redaction and accept the reviewed redaction.';
    case 'reporter_consent_missing':
      return 'Reporter consent to share this report is missing. Generating or sending a link is blocked until valid consent is recorded.';
    case 'dryrun_inbox_not_configured':
      return 'The test recipient inbox is not configured. Contact your administrator.';
    case 'dryrun_inbox_invalid':
      return 'The test recipient inbox is invalid. Contact your administrator.';
    case 'report_not_found':
      return 'This report could not be found. Refresh the admin panel and select the report again.';
    case 'report_not_eligible':
      return 'This report is not eligible for sharing. Check its status before continuing.';
    case 'recipient_email_missing':
      return 'Enter a valid recipient email address before sending the link.';
    default:
      if (error.startsWith('Too many requests. Automatic refresh will resume after ')) {
        return 'Too many requests. Wait for automatic refresh to resume before trying again.';
      }
      return 'The action could not be completed. Refresh the report status before trying again. If the problem persists, contact your administrator.';
  }
}
