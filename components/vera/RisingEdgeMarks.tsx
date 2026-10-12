import { useEffect, useRef } from 'react';
import styles from './RisingEdgeMarks.module.css';

type Spring = { x: number; v: number };
type Punch = { element: HTMLDivElement; y: number; on: number; off: number; scale: number };
const clamp = (value: number, min: number, max: number) => Math.max(min, Math.min(max, value));

// Fixed substeps keep the reference's heavy drive and quick registration step
// stable even when the browser drops a frame.
function integrate(spring: Spring, goal: number, dt: number, frequency: number, damping: number) {
    const steps = Math.max(1, Math.ceil(dt * 960));
    const h = dt / steps;
    for (let i = 0; i < steps; i++) {
        spring.v += (frequency ** 2 * (goal - spring.x) - 2 * damping * frequency * spring.v) * h;
        spring.x += spring.v * h;
    }
}

/** Tractor-feed punches are attached to the paper, never recycled while scrolling. */
export function RisingEdgeMarks() {
    const layerRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const layer = layerRef.current;
        const page = layer?.parentElement;
        if (!layer || !page) return;
        const root = document.documentElement;
        const enabled = matchMedia('(min-width: 768px) and (prefers-reduced-motion: no-preference)');
        const drive = { x: window.scrollY, v: 0 };
        const output = { ...drive };
        const driveFrequency = Math.sqrt(0.044) * 60;
        const driveDamping = (-Math.log(0.66) * 60) / (2 * driveFrequency);
        let punches: Punch[] = [];
        let pitch = 32,
            origin = 0,
            viewport = 0,
            max = 0;
        let raw = window.scrollY,
            target = raw,
            written = raw,
            lastY = raw;
        let driving = false,
            holdUntil = 0,
            frame = 0,
            lastFrame = 0;
        let lastInput = -Infinity,
            lastMove = -Infinity,
            lastWheel = -Infinity;
        let direction = 1,
            sweepDirection = 1,
            sweepAt = 0;
        let state: 'idle' | 'engaged' | 'retracting' = 'idle';
        const bootAt = performance.now();

        const available = () => enabled.matches && !document.hidden && !layer.closest('[inert]');
        const quantize = (y: number) => (y >= max - pitch / 2 ? max : clamp(Math.round(y / pitch) * pitch, 0, max));
        const sync = () => {
            driving = false;
            raw = target = written = lastY = window.scrollY;
            drive.x = output.x = raw;
            drive.v = output.v = 0;
        };
        const paint = (punch: Punch, scale: number) => {
            if (punch.scale === scale) return;
            punch.scale = scale;
            punch.element.style.setProperty('--punch-scale', String(scale));
        };
        const reset = () => {
            cancelAnimationFrame(frame);
            frame = 0;
            sync();
            state = 'idle';
            layer.dataset.feedState = state;
            punches.forEach((punch) => paint(punch, 0));
        };
        const engage = (now: number, dir: number) => {
            if (state === 'engaged') return false;
            state = 'engaged';
            layer.dataset.feedState = state;
            sweepAt = now;
            sweepDirection = dir;
            punches.forEach((punch) => {
                punch.on = Infinity;
                punch.off = Infinity;
            });
            return true;
        };

        const updatePunches = (now: number, y: number) => {
            if (state === 'engaged' && now - Math.max(lastInput, lastMove) > 520) {
                state = 'retracting';
                layer.dataset.feedState = state;
                sweepAt = now;
                sweepDirection = direction;
            }
            if (state === 'idle') return;
            let visible = false;
            for (const punch of punches) {
                const vy = origin + punch.y - y;
                if (vy < -2 * pitch || vy > viewport + 2 * pitch) {
                    paint(punch, 0);
                    punch.on = punch.off = Infinity;
                    continue;
                }
                const delay = clamp(sweepDirection > 0 ? viewport - vy : vy, 0, viewport) / 9;
                if (state === 'engaged' && punch.on === Infinity) punch.on = sweepAt + delay;
                if (state === 'retracting' && punch.off === Infinity) punch.off = sweepAt + delay;
                const age = now - (state === 'engaged' ? punch.on : punch.off);
                const scale =
                    state === 'engaged'
                        ? age < 0
                            ? 0
                            : age < 24
                              ? 0.42
                              : 1
                        : age < 0
                          ? punch.scale
                          : age < 24
                            ? Math.min(punch.scale, 0.42)
                            : 0;
                paint(punch, scale);
                visible ||= scale > 0;
            }
            if (state === 'retracting' && !visible) {
                state = 'idle';
                layer.dataset.feedState = state;
            }
        };

        const loop = (now: number) => {
            frame = 0;
            if (!available()) {
                reset();
                return;
            }
            const dt = clamp((now - lastFrame) / 1000, 0, 1 / 30);
            lastFrame = now;
            if (driving) {
                if (now >= holdUntil) integrate(drive, target, dt, driveFrequency, driveDamping);
                const speed = clamp((Math.abs(drive.v) - 300) / 800, 0, 1);
                const stepped = 1 - speed * speed * (3 - 2 * speed);
                integrate(output, drive.x + (quantize(drive.x) - drive.x) * stepped, dt, 2 * Math.PI * 14, 0.7);
                if (Math.abs(drive.x - target) < 0.02 && Math.abs(drive.v) < 0.5) {
                    drive.x = target;
                    drive.v = 0;
                }
                if (drive.x === target && Math.abs(output.x - target) < 0.02 && Math.abs(output.v) < 0.5) {
                    output.x = target;
                    output.v = 0;
                    driving = false;
                }
                const y = Math.round(clamp(output.x, 0, max) * devicePixelRatio) / devicePixelRatio;
                if (Math.abs(y - written) > 0.01) {
                    window.scrollTo({ top: y, behavior: 'instant' });
                    written = window.scrollY;
                }
            }
            if (Math.abs(written - lastY) > 0.01) {
                lastMove = now;
                direction = written > lastY ? 1 : -1;
                lastY = written;
            }
            updatePunches(now, written);
            if (driving || state !== 'idle') frame = requestAnimationFrame(loop);
        };
        const kick = () => {
            if (frame) return;
            lastFrame = performance.now();
            frame = requestAnimationFrame(loop);
        };
        const feed = (dy: number, absolute = false) => {
            const now = performance.now();
            if (!driving) sync();
            direction = (absolute ? dy - raw : dy) >= 0 ? 1 : -1;
            if (engage(now, direction)) holdUntil = now + 60;
            raw = clamp(absolute ? dy : raw + dy, 0, max);
            target = quantize(raw);
            lastInput = now;
            driving = true;
            kick();
        };

        // Leave controls, nested scrollers (including contained edges), and zoom native.
        const scrollsInside = (node: EventTarget | null, dy: number) => {
            for (let el = node instanceof Element ? node : null; el && el !== document.body; el = el.parentElement) {
                const css = getComputedStyle(el);
                if (!/^(auto|scroll)$/.test(css.overflowY)) continue;
                if (css.overscrollBehaviorY !== 'auto') return true;
                if (dy > 0 ? el.scrollTop + el.clientHeight < el.scrollHeight - 1 : el.scrollTop > 0) return true;
            }
            return false;
        };
        const wheel = (event: WheelEvent) => {
            if (!available() || event.defaultPrevented || event.ctrlKey || event.metaKey || !event.deltaY) return;
            if (Math.abs(event.deltaX) > Math.abs(event.deltaY) || scrollsInside(event.target, event.deltaY)) return;
            event.preventDefault();
            let dy = event.deltaY * (event.deltaMode === 1 ? 40 : event.deltaMode === 2 ? viewport : 1);
            const now = performance.now();
            if (now - lastWheel > 160 && Math.abs(dy) < pitch) dy = Math.sign(dy) * pitch;
            lastWheel = now;
            feed(dy);
        };
        const keydown = (event: KeyboardEvent) => {
            if (!available() || event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey) return;
            const active = document.activeElement;
            if (
                active?.closest(
                    'input, textarea, select, button, summary, [contenteditable]:not([contenteditable="false"]), [role="slider"], [role="tab"], [role="menuitem"], [role="listbox"]',
                )
            )
                return;
            const pageStep = Math.max(pitch, Math.floor((viewport * 0.875) / pitch) * pitch);
            const keys: Record<string, number> = {
                ArrowDown: 2 * pitch,
                ArrowUp: -2 * pitch,
                PageDown: pageStep,
                PageUp: -pageStep,
                ' ': event.shiftKey ? -pageStep : pageStep,
                Home: -raw,
                End: max - raw,
            };
            const dy = keys[event.key];
            if (dy === undefined || scrollsInside(active, dy)) return;
            event.preventDefault();
            feed(
                event.key === 'Home' ? 0 : event.key === 'End' ? max : dy,
                event.key === 'Home' || event.key === 'End',
            );
        };
        const scroll = () => {
            if (Math.abs(window.scrollY - written) < 1) return;
            const dir = window.scrollY > written ? 1 : -1;
            sync(); // Touch, scrollbar dragging, anchors, focus, and history restoration win.
            if (!available() || performance.now() - bootAt < 600) return;
            const now = performance.now();
            engage(now, dir);
            lastInput = lastMove = now;
            direction = dir;
            kick();
        };
        const interrupt = () => reset();

        const measure = () => {
            reset();
            origin = page.getBoundingClientRect().top + window.scrollY + page.clientTop;
            viewport = root.clientHeight;
            max = Math.max(0, root.scrollHeight - viewport);
            const headline = page.querySelector<HTMLElement>('main h1');
            const footer = page.querySelector('footer');
            // The hero headline enters with translateY(32px). Its positioned
            // parent stays still, so offsetTop measures the settled layout
            // even before that transform has finished animating.
            const headlineParent = headline?.offsetParent;
            const headlineTop =
                headline && headlineParent
                    ? headlineParent.getBoundingClientRect().top + headlineParent.clientTop + headline.offsetTop
                    : page.getBoundingClientRect().top;
            const top = Math.ceil(headlineTop + window.scrollY - origin);
            const bottom =
                (footer?.getBoundingClientRect().top ?? page.getBoundingClientRect().bottom) + window.scrollY - origin;
            const patterns = Array.from(page.querySelectorAll('[data-edge-pattern]'), (pattern) => {
                const rect = pattern.getBoundingClientRect();
                return { top: rect.top + window.scrollY - origin, bottom: rect.bottom + window.scrollY - origin };
            });
            const probe = document.createElement('span');
            probe.className = styles.bar;
            layer.replaceChildren(probe);
            const height = parseFloat(getComputedStyle(probe).height) || 8;
            pitch = Math.max(16, Math.round(height * 4));
            const fragment = document.createDocumentFragment();
            punches = [];
            // Space the decoration independently of the existing scroll registration step.
            for (let y = top; y + height <= bottom; y += pitch * 2) {
                if (patterns.some((pattern) => y + height > pattern.top - height && y < pattern.bottom + height)) continue;
                const element = document.createElement('div');
                element.className = styles.row;
                element.style.top = `${y}px`;
                for (const side of ['left', 'right']) {
                    const bar = document.createElement('span');
                    bar.className = styles.bar;
                    bar.dataset.side = side;
                    element.append(bar);
                }
                fragment.append(element);
                punches.push({ element, y, on: Infinity, off: Infinity, scale: 0 });
            }
            layer.replaceChildren(fragment);
        };

        measure();
        const observer = new ResizeObserver(measure);
        observer.observe(page);
        window.addEventListener('resize', measure);
        window.addEventListener('wheel', wheel, { passive: false });
        window.addEventListener('keydown', keydown);
        window.addEventListener('scroll', scroll, { passive: true });
        window.addEventListener('pointerdown', interrupt, { passive: true });
        window.addEventListener('touchstart', interrupt, { passive: true });
        document.addEventListener('visibilitychange', interrupt);
        enabled.addEventListener('change', interrupt);
        return () => {
            reset();
            observer.disconnect();
            window.removeEventListener('resize', measure);
            window.removeEventListener('wheel', wheel);
            window.removeEventListener('keydown', keydown);
            window.removeEventListener('scroll', scroll);
            window.removeEventListener('pointerdown', interrupt);
            window.removeEventListener('touchstart', interrupt);
            document.removeEventListener('visibilitychange', interrupt);
            enabled.removeEventListener('change', interrupt);
            layer.replaceChildren();
        };
    }, []);

    return <div ref={layerRef} className={styles.layer} aria-hidden="true" data-rising-marks="" />;
}
