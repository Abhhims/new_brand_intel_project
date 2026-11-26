/** Human label for an email intake channel (backend EmailMessage.channel). */
const CHANNEL_LABELS: Record<string, string> = {
  upload: "Upload",
  mailbox: "Mailbox",
  graph: "Microsoft 365",
  gmail: "Google",
}

export function channelLabelFor(channel: string): string {
  return CHANNEL_LABELS[channel] ?? channel
}
