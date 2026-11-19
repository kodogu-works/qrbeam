/** Tracks the physical Enter key across screens, including key repeat and blur. */
export class EnterGuard {
  private held = false;
  private needsRelease = false;
  private shownAt = Number.POSITIVE_INFINITY;

  constructor(private readonly delayMs = 1500) {}

  show(now: number): void {
    this.shownAt = now;
    this.needsRelease = this.held;
  }

  blur(): void {
    this.held = true;
    this.needsRelease = true;
  }

  keyup(key: string): void {
    if (key !== 'Enter') return;
    this.held = false;
    this.needsRelease = false;
  }

  keydown(key: string, repeat: boolean, now: number): boolean {
    if (key !== 'Enter') return false;
    const allowed = !repeat && !this.held && !this.needsRelease && now - this.shownAt >= this.delayMs;
    this.held = true;
    return allowed;
  }

  ready(now: number): boolean {
    return !this.needsRelease && !this.held && now - this.shownAt >= this.delayMs;
  }
}
