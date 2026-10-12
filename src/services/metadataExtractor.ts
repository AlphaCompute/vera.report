import { logger } from '../utils/logger';
/**
 * Metadata Extractor Service
 * Extracts all detectable metadata from uploaded files
 * for user review before stripping
 */

import ExifReader from 'exifreader';

export interface ExtractedMetadata {
  // Image EXIF
  camera?: {
    make?: string;
    model?: string;
    lens?: string;
    software?: string;
    serialNumber?: string;
  };
  // GPS Data
  gps?: {
    latitude?: number;
    longitude?: number;
    altitude?: number;
    locationName?: string; // Reverse geocoded if possible
  };
  // Date/Time
  datetime?: {
    taken?: string;
    digitized?: string;
    modified?: string;
  };
  // Device Info
  device?: {
    owner?: string;
    artist?: string;
    copyright?: string;
    hostname?: string;
  };
  // Document Metadata
  document?: {
    author?: string;
    creator?: string;
    producer?: string;
    title?: string;
    subject?: string;
    company?: string;
  };
  // File Info
  file: {
    name: string;
    type: string;
    size: number;
    dimensions?: { width: number; height: number };
  };
  // Summary for quick display
  summary: {
    hasLocation: boolean;
    hasDeviceInfo: boolean;
    hasPersonalInfo: boolean;
    hasDates: boolean;
    riskLevel: 'low' | 'medium' | 'high';
    itemCount: number;
  };
  // Raw items for checkbox display
  items: MetadataItem[];
}

export interface MetadataItem {
  id: string;
  category: 'location' | 'device' | 'personal' | 'datetime' | 'technical';
  label: string;
  value: string;
  risk: 'low' | 'medium' | 'high';
  icon: string;
  stripByDefault: boolean;
}

export class MetadataExtractorService {

  /**
   * Extract all metadata from a file buffer
   */
  async extractMetadata(
    buffer: Buffer,
    fileName: string,
    mimeType: string
  ): Promise<ExtractedMetadata> {
    const items: MetadataItem[] = [];
    const metadata: ExtractedMetadata = {
      file: {
        name: fileName,
        type: mimeType,
        size: buffer.length,
      },
      summary: {
        hasLocation: false,
        hasDeviceInfo: false,
        hasPersonalInfo: false,
        hasDates: false,
        riskLevel: 'low',
        itemCount: 0,
      },
      items: [],
    };

    // Extract based on file type
    if (mimeType.startsWith('image/')) {
      await this.extractImageMetadata(buffer, metadata, items);
    } else if (mimeType === 'application/pdf') {
      this.extractPdfMetadata(buffer, metadata, items);
    } else if (mimeType.includes('video')) {
      this.extractVideoMetadata(buffer, metadata, items);
    }

    // Add file info items
    items.push({
      id: 'file_name',
      category: 'technical',
      label: 'File Name',
      value: fileName,
      risk: fileName.toLowerCase().includes('img_') ? 'low' : 'medium',
      icon: '📄',
      stripByDefault: false,
    });

    // Calculate summary
    metadata.summary = this.calculateSummary(items, metadata);
    metadata.items = items;

    return metadata;
  }

  /**
   * Extract EXIF and other metadata from images
   */
  private async extractImageMetadata(
    buffer: Buffer,
    metadata: ExtractedMetadata,
    items: MetadataItem[]
  ): Promise<void> {
    try {
      const tags = ExifReader.load(buffer, { expanded: true });

      // Camera Info
      if (tags.exif) {
        const exif = tags.exif;

        if (exif.Make?.description || exif.Model?.description) {
          metadata.camera = {
            make: exif.Make?.description,
            model: exif.Model?.description,
            lens: exif.LensModel?.description,
            software: exif.Software?.description,
          };

          if (exif.Make?.description) {
            items.push({
              id: 'camera_make',
              category: 'device',
              label: 'Camera Make',
              value: exif.Make.description,
              risk: 'medium',
              icon: '📷',
              stripByDefault: true,
            });
          }

          if (exif.Model?.description) {
            items.push({
              id: 'camera_model',
              category: 'device',
              label: 'Device Model',
              value: exif.Model.description,
              risk: 'medium',
              icon: '📱',
              stripByDefault: true,
            });
          }

          if (exif.Software?.description) {
            items.push({
              id: 'software',
              category: 'device',
              label: 'Software',
              value: exif.Software.description,
              risk: 'low',
              icon: '💻',
              stripByDefault: true,
            });
          }
        }

        // Date/Time
        if (exif.DateTimeOriginal?.description || exif.DateTime?.description) {
          metadata.datetime = {
            taken: exif.DateTimeOriginal?.description,
            digitized: exif.DateTimeDigitized?.description,
            modified: exif.DateTime?.description,
          };

          if (exif.DateTimeOriginal?.description) {
            items.push({
              id: 'date_taken',
              category: 'datetime',
              label: 'Date Taken',
              value: this.formatDate(exif.DateTimeOriginal.description),
              risk: 'medium',
              icon: '📅',
              stripByDefault: false, // Keep for evidence timeline
            });
          }
        }

        // Owner/Artist
        if (exif.Artist?.description) {
          metadata.device = metadata.device || {};
          metadata.device.artist = exif.Artist.description;
          items.push({
            id: 'artist',
            category: 'personal',
            label: 'Artist/Owner',
            value: exif.Artist.description,
            risk: 'high',
            icon: '👤',
            stripByDefault: true,
          });
        }

        if (exif.Copyright?.description) {
          metadata.device = metadata.device || {};
          metadata.device.copyright = exif.Copyright.description;
          items.push({
            id: 'copyright',
            category: 'personal',
            label: 'Copyright',
            value: exif.Copyright.description,
            risk: 'high',
            icon: '©️',
            stripByDefault: true,
          });
        }
      }

      // GPS Data
      if (tags.gps) {
        const gps = tags.gps;
        if (gps.Latitude !== undefined && gps.Longitude !== undefined) {
          metadata.gps = {
            latitude: gps.Latitude,
            longitude: gps.Longitude,
            altitude: gps.Altitude,
          };

          items.push({
            id: 'gps_location',
            category: 'location',
            label: 'GPS Location',
            value: `${gps.Latitude.toFixed(4)}°, ${gps.Longitude.toFixed(4)}°`,
            risk: 'high',
            icon: '📍',
            stripByDefault: true,
          });

          if (gps.Altitude !== undefined) {
            items.push({
              id: 'gps_altitude',
              category: 'location',
              label: 'Altitude',
              value: `${gps.Altitude.toFixed(1)}m`,
              risk: 'medium',
              icon: '⛰️',
              stripByDefault: true,
            });
          }
        }
      }

      // Image dimensions
      if (tags.file) {
        const file = tags.file;
        if (file['Image Width'] && file['Image Height']) {
          metadata.file.dimensions = {
            width: file['Image Width'].value,
            height: file['Image Height'].value,
          };
        }
      }

    } catch (error) {
      logger.warn('[METADATA] EXIF extraction failed:', error);
    }
  }

  /**
   * Extract metadata from PDF documents
   */
  private extractPdfMetadata(
    buffer: Buffer,
    metadata: ExtractedMetadata,
    items: MetadataItem[]
  ): void {
    try {
      const text = buffer.toString('binary');

      // Look for PDF metadata patterns
      const authorMatch = text.match(/\/Author\s*\(([^)]+)\)/);
      const creatorMatch = text.match(/\/Creator\s*\(([^)]+)\)/);
      const producerMatch = text.match(/\/Producer\s*\(([^)]+)\)/);
      const titleMatch = text.match(/\/Title\s*\(([^)]+)\)/);

      metadata.document = {};

      if (authorMatch) {
        metadata.document.author = authorMatch[1];
        items.push({
          id: 'pdf_author',
          category: 'personal',
          label: 'Document Author',
          value: authorMatch[1],
          risk: 'high',
          icon: '👤',
          stripByDefault: true,
        });
      }

      if (creatorMatch) {
        metadata.document.creator = creatorMatch[1];
        items.push({
          id: 'pdf_creator',
          category: 'device',
          label: 'Creator App',
          value: creatorMatch[1],
          risk: 'medium',
          icon: '💻',
          stripByDefault: true,
        });
      }

      if (producerMatch) {
        metadata.document.producer = producerMatch[1];
        items.push({
          id: 'pdf_producer',
          category: 'device',
          label: 'PDF Producer',
          value: producerMatch[1],
          risk: 'low',
          icon: '🖨️',
          stripByDefault: true,
        });
      }

      if (titleMatch) {
        metadata.document.title = titleMatch[1];
        items.push({
          id: 'pdf_title',
          category: 'technical',
          label: 'Document Title',
          value: titleMatch[1],
          risk: 'low',
          icon: '📑',
          stripByDefault: false,
        });
      }
    } catch (error) {
      logger.warn('[METADATA] PDF extraction failed:', error);
    }
  }

  /**
   * Extract metadata from video files
   */
  private extractVideoMetadata(
    buffer: Buffer,
    metadata: ExtractedMetadata,
    items: MetadataItem[]
  ): void {
    // Basic video metadata detection
    // Full implementation would need ffprobe or similar
    items.push({
      id: 'video_note',
      category: 'technical',
      label: 'Video File',
      value: 'Video metadata extraction limited',
      risk: 'medium',
      icon: '🎬',
      stripByDefault: true,
    });
  }

  /**
   * Calculate summary from extracted items
   */
  private calculateSummary(
    items: MetadataItem[],
    metadata: ExtractedMetadata
  ): ExtractedMetadata['summary'] {
    const hasLocation = items.some(i => i.category === 'location');
    const hasDeviceInfo = items.some(i => i.category === 'device');
    const hasPersonalInfo = items.some(i => i.category === 'personal');
    const hasDates = items.some(i => i.category === 'datetime');

    // Calculate risk level
    let riskLevel: 'low' | 'medium' | 'high' = 'low';
    if (hasLocation || hasPersonalInfo) {
      riskLevel = 'high';
    } else if (hasDeviceInfo) {
      riskLevel = 'medium';
    }

    return {
      hasLocation,
      hasDeviceInfo,
      hasPersonalInfo,
      hasDates,
      riskLevel,
      itemCount: items.filter(i => i.stripByDefault).length,
    };
  }

  /**
   * Format EXIF date string
   */
  private formatDate(exifDate: string): string {
    try {
      // EXIF format: "YYYY:MM:DD HH:MM:SS"
      const [date, time] = exifDate.split(' ');
      const [y, m, d] = date.split(':');
      return `${d}/${m}/${y} ${time || ''}`.trim();
    } catch {
      return exifDate;
    }
  }
}

export const metadataExtractorService = new MetadataExtractorService();
