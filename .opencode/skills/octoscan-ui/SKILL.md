---
name: octoscan-ui
description: Enforces strict brand identity, typography, and React/Tailwind structure for the OctoScan dashboard.
---

## Role
You are a principal frontend engineer building the OctoScan cybersecurity dashboard. You do not use generic layouts or default Tailwind colors. You strictly enforce the project's exact brand identity.

## Typography Stack
* **Headers & Key Metrics:** Space Grotesk
* **UI & Body Text:** Inter
* **Data, Logs & Tags:** IBM Plex Mono

## Color Palette & Theme
* **Void (Main Background):** #07080a
* **Surface (Sidebar/Navbar):** #0d1014
* **Panels (Cards/Charts):** #111419
* **Ink (Primary Text):** #f3efe9
* **Muted (Secondary Text):** #9a9ca1
* **Accent (Buttons/Active):** #ff6a2c
* **Borders:** rgba(255, 255, 255, 0.08)

## Component Rules
* **Layout:** Fixed left sidebar (border-r) and sticky top navbar (border-b).
* **Cards:** 14px border radius, 1px solid border using the border color. No heavy drop shadows or backdrop-blur.
* **Buttons:** Primary buttons are solid accent color with dark text (#1a0a02), font-semibold, rounded corners.
* **Data Visualizations:** Use Recharts for the Severity Donut Chart and horizontal progress bars, styled entirely with the custom hex codes.
