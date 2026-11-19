import { describe, expect, it } from 'vitest';
import { EnterGuard } from '../security/enter-guard';

describe('S4 Enter guard', () => {
  it('requires the guard interval and a fresh nonrepeating keydown', () => {
    const guard = new EnterGuard();
    guard.show(0);
    expect(guard.keydown('Enter', false, 1000)).toBe(false);
    guard.keyup('Enter');
    expect(guard.keydown('Enter', true, 2000)).toBe(false);
    guard.keyup('Enter');
    expect(guard.keydown('Enter', false, 2100)).toBe(true);
    expect(guard.keydown('Enter', false, 2200)).toBe(false);
  });

  it('requires release when Enter was held before S4', () => {
    const guard = new EnterGuard();
    guard.keydown('Enter', false, 0);
    guard.show(100);
    expect(guard.keydown('Enter', true, 5000)).toBe(false);
    guard.keyup('Enter');
    expect(guard.keydown('Enter', false, 5001)).toBe(true);
  });

  it('requires keyup after blur, including blur before S4', () => {
    const guard = new EnterGuard();
    guard.blur();
    guard.show(0);
    expect(guard.keydown('Enter', false, 3000)).toBe(false);
    guard.keyup('Enter');
    expect(guard.keydown('Enter', false, 3001)).toBe(true);
    guard.blur();
    expect(guard.ready(5000)).toBe(false);
  });
});
