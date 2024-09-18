import globals from "globals";
import pluginJs from "@eslint/js";

export default [
    {
        languageOptions: {
            globals: globals.browser,
        },
        files: ["docs/**/*.js"],
        // argsIgnorePattern: "^_",
    },
    pluginJs.configs.recommended,
];
