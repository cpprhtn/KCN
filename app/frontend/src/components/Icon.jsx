export function Icon({ name }) {
  return <svg className="ic" aria-hidden="true"><use href={"#i-" + name} /></svg>;
}

// One hidden sprite; every <Icon> points into it.
export function IconSprite() {
  return (
    <svg width="0" height="0" style={{ position: "absolute" }} aria-hidden="true">
      <symbol id="i-logo" viewBox="0 0 24 24"><path d="M12 3.2 19.5 6v5.6c0 4.4-3.1 7.9-7.5 9.2-4.4-1.3-7.5-4.8-7.5-9.2V6z"/><path d="m8.8 12.2 2.3 2.3 4.3-4.6"/></symbol>
      <symbol id="i-search" viewBox="0 0 24 24"><circle cx="11" cy="11" r="6.5"/><path d="m20 20-4-4"/></symbol>
      <symbol id="i-today" viewBox="0 0 24 24"><rect x="3.5" y="5" width="17" height="15.5" rx="3.5"/><path d="M3.5 10h17M8 3v4M16 3v4"/><circle cx="12" cy="15" r="1.6" fill="currentColor" stroke="none"/></symbol>
      <symbol id="i-flame" viewBox="0 0 24 24"><path d="M12 3c.8 3.2 5.5 5.3 5.5 10.2a5.5 5.5 0 0 1-11 0c0-2.3 1.1-3.8 2.3-4.9.1 2 1 3.1 2.2 3.1 0-3.1-1-5.2 1-8.4z"/></symbol>
      <symbol id="i-update" viewBox="0 0 24 24"><path d="M19.5 12a7.5 7.5 0 1 1-2.2-5.3"/><path d="M19.5 4.5v4.2h-4.2"/><path d="M12 8.5V12l2.5 1.5"/></symbol>
      <symbol id="i-box" viewBox="0 0 24 24"><path d="M3.5 7.5 12 3.5l8.5 4v9L12 20.5l-8.5-4z"/><path d="M3.5 7.5 12 11.5l8.5-4M12 11.5v9"/></symbol>
      <symbol id="i-flag" viewBox="0 0 24 24"><path d="M5.5 21V4h11l-2 4 2 4h-11"/></symbol>
      <symbol id="i-shield" viewBox="0 0 24 24"><path d="M12 3.2 19.5 6v5.6c0 4.4-3.1 7.9-7.5 9.2-4.4-1.3-7.5-4.8-7.5-9.2V6z"/><path d="M12 8v4.5M12 15.8v.2"/></symbol>
      <symbol id="i-book" viewBox="0 0 24 24"><path d="M5 5.5A2.5 2.5 0 0 1 7.5 3H19v15H7.5A2.5 2.5 0 0 0 5 20.5z"/><path d="M5 20.5A2.5 2.5 0 0 0 7.5 23H19"/></symbol>
      <symbol id="i-spark" viewBox="0 0 24 24"><path d="M12 3.5l1.9 5.3 5.3 1.9-5.3 1.9L12 18l-1.9-5.4-5.3-1.9 5.3-1.9z"/><path d="M18.5 15.5l.7 1.8 1.8.7-1.8.7-.7 1.8-.7-1.8-1.8-.7 1.8-.7z"/></symbol>
      <symbol id="i-copy" viewBox="0 0 24 24"><rect x="8.5" y="8.5" width="11" height="11" rx="2.5"/><path d="M15.5 8.5V6.5a2 2 0 0 0-2-2h-7a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h2"/></symbol>
      <symbol id="i-moon" viewBox="0 0 24 24"><path d="M19.5 14.6A7.8 7.8 0 0 1 9.4 4.5 7.8 7.8 0 1 0 19.5 14.6z"/></symbol>
      <symbol id="i-sun" viewBox="0 0 24 24"><circle cx="12" cy="12" r="4"/><path d="M12 2.5v2M12 19.5v2M4.6 4.6 6 6M18 18l1.4 1.4M2.5 12h2M19.5 12h2M4.6 19.4 6 18M18 6l1.4-1.4"/></symbol>
      <symbol id="i-arrow" viewBox="0 0 24 24"><path d="M5 12h14M13 6l6 6-6 6"/></symbol>
    </svg>
  );
}
