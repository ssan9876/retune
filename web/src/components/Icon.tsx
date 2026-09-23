/** Icon draws the small line glyphs the nav and top bar use. They are inline
 * SVG paths rather than an icon package: a dozen 16px glyphs are not worth a
 * dependency, and the console ships no network requests it does not need.
 * Every glyph is drawn on the same 16x16 grid with the same 1.4 stroke, which
 * is what keeps a set drawn by hand looking like a set. */
const PATHS: Record<string, string> = {
  home: "M2.5 7.5 8 3l5.5 4.5M4 7v6h8V7",
  device: "M2.5 3.5h11v7h-11zM6 13h4M8 10.5v2.5",
  group: "M6 7.5a2 2 0 1 0 0-4 2 2 0 0 0 0 4ZM2.5 13c0-2 1.6-3.2 3.5-3.2S9.5 11 9.5 13M11 5.2a1.8 1.8 0 0 1 0 3.6M12 9.8c1.2.4 1.9 1.4 1.9 3.2",
  key: "M9.5 6.5a2.5 2.5 0 1 1 3 3L11 11v1.5H9.5V14H7v-2.2l2.5-2.5ZM11.7 7.8h.01",
  terminal: "M2.5 3.5h11v9h-11zM5 6.5l2 2-2 2M8.5 10.5h3",
  app: "M3 3h4.2v4.2H3zM8.8 3H13v4.2H8.8zM3 8.8h4.2V13H3zM8.8 8.8H13V13H8.8z",
  script: "M4 2.5h6l2.5 2.5v8.5H4zM9.5 2.5V5H12M6 8h4M6 10.5h4",
  profile: "M8 2.5 3 4.5v4c0 3 2.2 4.6 5 5.5 2.8-.9 5-2.5 5-5.5v-4zM6 8l1.5 1.5L10.5 6.5",
  update: "M13 8a5 5 0 1 1-1.6-3.7M13 2.8V5.3h-2.5",
  shield: "M8 2.5 3.5 4.3v4.2c0 2.8 1.9 4.4 4.5 5.2 2.6-.8 4.5-2.4 4.5-5.2V4.3z",
  person: "M8 8a2.4 2.4 0 1 0 0-4.8A2.4 2.4 0 0 0 8 8ZM3.5 13.5c0-2.4 2-3.8 4.5-3.8s4.5 1.4 4.5 3.8",
  bell: "M8 2.5a3.5 3.5 0 0 1 3.5 3.5v3l1 1.5h-9l1-1.5v-3A3.5 3.5 0 0 1 8 2.5ZM6.5 10.5a1.5 1.5 0 0 0 3 0",
  list: "M3 4.5h10M3 8h10M3 11.5h10",
  check: "M3 8.5 6.5 12 13 4.5",
  mail: "M2.5 4h11v8h-11zM2.5 4.5 8 9l5.5-4.5",
  clock: "M8 13.5a5.5 5.5 0 1 0 0-11 5.5 5.5 0 0 0 0 11ZM8 5v3.2l2 1.3",
  search: "M7.2 11.4a4.2 4.2 0 1 0 0-8.4 4.2 4.2 0 0 0 0 8.4ZM10.4 10.4 13.5 13.5",
  menu: "M2.5 4.5h11M2.5 8h11M2.5 11.5h11",
  mark: "M3 11V5M6.3 13V3M9.7 11.5V4.5M13 9.5V6.5",
};

export function Icon({ name }: { name: string }) {
  const d = PATHS[name] ?? PATHS.list;
  return (
    <svg
      className="icon"
      viewBox="0 0 16 16"
      width="16"
      height="16"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.4"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      <path d={d} />
    </svg>
  );
}
