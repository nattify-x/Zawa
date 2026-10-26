/**
 * Zawa Brand Theme
 * Pure TypeScript token definitions without VS Code dependencies.
 */
export const theme = {
  bg: '#0B0B0C',
  surface: '#151517',
  text: '#EDEDED',
  red: '#D7263D',
  yellow: '#F2B705',
  orange: '#F28C28',
  muted: '#8A8A8E',
} as const;

export type Theme = typeof theme;
