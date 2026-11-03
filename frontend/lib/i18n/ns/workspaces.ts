import { defineMessages } from "../core";

/** Workspace switcher (sidebar) and Settings → Region and formats. */
export const workspaces = defineMessages({
  en: {
    label: "Workspace",
    invited: "invited",
    home: "home",
    switchFailed: "Couldn't switch workspace.",
    createNew: "New workspace",
    namePlaceholder: "Workspace name",
    create: "Create",
    cancel: "Cancel",
    createFailed: "Couldn't create the workspace.",
    regionalTitle: "Region and formats",
    regionalHint: "Times are stored in UTC and shown in your time zone. The workspace time zone is used for reports and emails.",
    dataRegion: "Data region",
    workspaceDefaults: "Workspace defaults",
    myPreferences: "My preferences",
    timezone: "Time zone",
    browserZone: "This browser's time zone",
    dateFormat: "Date format",
    timeFormat: "Time format",
    followLanguage: "As the language writes it",
    h24: "24-hour",
    h12: "12-hour",
    currency: "Billing currency",
    save: "Save",
    saved: "Saved",
    saveFailed: "Couldn't save.",
  },
});
