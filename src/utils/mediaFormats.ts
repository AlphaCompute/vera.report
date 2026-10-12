// Browser-safe format registry shared by upload validation and the sanitizer.
export const MEDIA_FORMATS: Record<string, { input: string; output: string; video: boolean }> = {
  'audio/mpeg': { input: 'mp3', output: 'mp3', video: false },
  'audio/wav': { input: 'wav', output: 'wav', video: false },
  'audio/x-wav': { input: 'wav', output: 'wav', video: false },
  'audio/mp4': { input: 'mov', output: 'ipod', video: false },
  'audio/x-m4a': { input: 'mov', output: 'ipod', video: false },
  'audio/aac': { input: 'aac', output: 'adts', video: false },
  'audio/ogg': { input: 'ogg', output: 'ogg', video: false },
  'audio/opus': { input: 'ogg', output: 'ogg', video: false },
  'audio/flac': { input: 'flac', output: 'flac', video: false },
  'audio/x-flac': { input: 'flac', output: 'flac', video: false },
  'audio/webm': { input: 'matroska', output: 'webm', video: false },
  'video/webm': { input: 'matroska', output: 'webm', video: true },
  'video/x-matroska': { input: 'matroska', output: 'matroska', video: true },
  'video/x-msvideo': { input: 'avi', output: 'avi', video: true },
  'video/ogg': { input: 'ogg', output: 'ogg', video: true },
  'video/mp4': { input: 'mov', output: 'mp4', video: true },
  'video/quicktime': { input: 'mov', output: 'mov', video: true },
};

