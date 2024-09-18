import globals from "globals";
import pluginJs from "@eslint/js";

export default [
    {
        rules: {
            "no-unused-vars": [
                "error",
                {
                    argsIgnorePattern: "^_",
                    destructuredArrayIgnorePattern: "^_"
                },
            ],
        },
        languageOptions: {
            globals: globals.browser,
        },
        files: ["docs/**/*.js"],
    },
    pluginJs.configs.recommended,
];
