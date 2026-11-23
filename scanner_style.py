"""Styles for the CyberGuard shell and scanner screen."""

SCANNER_CSS = """
<style>
.stApp:has(.st-key-cyberguard-header) {
    --cg-background: #fcf7f3;
    --cg-surface: #fefefe;
    --cg-ink: #0b1429;
    --cg-muted: #415064;
    --cg-line: #d4d6db;
    --cg-primary: #cc4c24;
    --cg-primary-hover: #bd4320;
    --cg-focus: #208d91;
    --cg-page-gutter: clamp(1rem, 2.05vw, 2.5rem);
    --cg-shield-check: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48' fill='none' stroke='black' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M24 4 41 10v12c0 9-7 16-17 22C14 38 7 31 7 22V10Z M17 23l5 5 10-10'/%3E%3C/svg%3E");
    --cg-shield-alert: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48' fill='none' stroke='black' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M24 4 41 10v12c0 9-7 16-17 22C14 38 7 31 7 22V10Z M24 15v11 M24 32h.01'/%3E%3C/svg%3E");
    color: var(--cg-ink);
}

.stApp:has(.st-key-cyberguard-header) [data-testid="stAppViewContainer"] {
    background: var(--cg-background);
}

.stApp:has(.st-key-cyberguard-header) [data-testid="stHeader"] {
    display: none;
}

.stApp:has(.st-key-cyberguard-header) [data-testid="stMainBlockContainer"] {
    max-width: 104rem;
    padding: 0 var(--cg-page-gutter) 2.5rem;
}

.st-key-cyberguard-header {
    min-width: calc(100% + 2 * var(--cg-page-gutter));
    min-height: 4.65rem;
    justify-content: center;
    margin-inline: calc(-1 * var(--cg-page-gutter));
    padding: .35rem var(--cg-page-gutter);
    border-bottom: 1px solid #bfc0c4;
}

.st-key-cyberguard-header [data-testid="stHorizontalBlock"] {
    align-items: center;
}

.st-key-cyberguard-header [data-testid="stHorizontalBlock"] [data-testid="stHorizontalBlock"] {
    max-width: 29.5rem;
    margin-inline-start: auto;
}

.st-key-cyberguard_brand button {
    position: relative;
    min-height: 3.5rem;
    padding: .1rem 0 .1rem clamp(3rem, 5.5vw, 5.2rem);
    border: 0;
    background: transparent;
    color: var(--cg-ink);
    text-align: start;
}

.st-key-cyberguard_brand button:hover {
    color: var(--cg-primary-hover);
}

.st-key-cyberguard_brand button::before,
.st-key-cyberguard_brand button::after {
    position: absolute;
    inset-inline-start: clamp(.13rem, 1.05vw, 1.05rem);
    top: 50%;
    width: clamp(2rem, 3.55vw, 3.35rem);
    height: clamp(2.05rem, 3.65vw, 3.45rem);
    transform: translateY(-50%);
    content: "";
    pointer-events: none;
}

.st-key-cyberguard_brand button::before {
    background: linear-gradient(136deg, #081629 43%, #fff 44% 48%, #ec653d 49% 76%, #c74927 77%);
    clip-path: polygon(50% 0, 98% 17%, 98% 53%, 92% 67%, 75% 85%, 50% 100%,
                       27% 86%, 10% 69%, 2% 52%, 2% 17%);
}

.st-key-cyberguard_brand button::after {
    background: #fff;
    clip-path: polygon(18% 29%, 51% 34%, 86% 13%, 93% 17%, 55% 41%, 55% 99%,
                       49% 99%, 49% 79%, 18% 55%, 18% 29%, 24% 38%, 24% 52%,
                       49% 70%, 49% 41%, 24% 38%);
}

.st-key-cyberguard_brand button p {
    font-size: clamp(1.25rem, 2.42vw, 2.32rem);
    font-weight: 790;
    letter-spacing: -.035em;
    line-height: 1.1;
}

.st-key-cyberguard-header :is(.st-key-nav_scanner, .st-key-nav_history, .st-key-nav_analytics) button {
    min-height: 3.25rem;
    padding: .45rem .45rem .4rem;
    border: 0;
    border-radius: .85rem;
    color: var(--cg-ink);
    background: transparent;
    box-shadow: none;
    white-space: nowrap;
}

.st-key-cyberguard-header :is(.st-key-nav_scanner, .st-key-nav_history, .st-key-nav_analytics) button p {
    font-size: clamp(.94rem, 1.75vw, 1.62rem);
    font-weight: 620;
}

.st-key-cyberguard-header [data-testid="stBaseButton-primary"] {
    position: relative;
}

.st-key-cyberguard-header :is(.st-key-nav_scanner, .st-key-nav_history, .st-key-nav_analytics)
[data-testid="stBaseButton-primary"] {
    color: #bd421c;
    background: #fbeae1;
}

.st-key-cyberguard-header [data-testid="stBaseButton-primary"]::after {
    position: absolute;
    inset: auto .5rem -.35rem;
    height: .23rem;
    background: var(--cg-primary);
    content: "";
}

.st-key-cyberguard-header :is(.st-key-nav_scanner, .st-key-nav_history, .st-key-nav_analytics) button:hover {
    color: #af3b19;
    background: #fbeae1;
}

.st-key-scanner {
    gap: clamp(1.25rem, 3vw, 2.65rem);
    padding-top: clamp(1.2rem, 2.45vw, 2.65rem);
    font-variant-numeric: tabular-nums;
}

.cg-scanner-heading {
    padding-inline: clamp(0rem, .65vw, .6rem);
}

.cg-scanner-heading h1 {
    margin: 0;
    padding: 0;
    color: var(--cg-ink);
    font-size: clamp(2rem, 3.78vw, 3.6rem);
    font-weight: 820;
    letter-spacing: -.037em;
    line-height: 1.08;
}

.cg-scanner-heading p {
    margin: .58rem 0 0;
    color: var(--cg-muted);
    font-size: clamp(1.05rem, 2.02vw, 1.9rem);
    line-height: 1.3;
}

.st-key-scanner [data-testid="stHorizontalBlock"]:has(.st-key-scanner-input):has(.st-key-scanner-report) {
    align-items: stretch;
    gap: clamp(.9rem, 1.25vw, 1.2rem);
}

.st-key-scanner [data-testid="stColumn"]:has(.st-key-scanner-input, .st-key-scanner-report) {
    min-width: 0;
    display: flex;
}

.st-key-scanner [data-testid="stColumn"]:has(.st-key-scanner-input, .st-key-scanner-report)
> [data-testid="stVerticalBlock"] > [data-testid="stLayoutWrapper"] {
    flex: 1;
}

.st-key-scanner :is(.st-key-scanner-input, .st-key-scanner-report) {
    flex: 1;
    min-width: 0;
    padding: clamp(1rem, 1.72vw, 1.65rem);
    border: 1px solid var(--cg-line);
    border-radius: .8rem;
    background: var(--cg-surface);
    box-shadow: 0 .25rem .65rem #0b142912;
}

.st-key-scanner-input {
    gap: clamp(1rem, 2.15vw, 1.9rem);
}

.st-key-scanner-report {
    gap: clamp(.85rem, 1.3vw, 1.2rem);
}

.st-key-scanner-input :is(h2, h3).cg-panel-title,
.st-key-scanner-input [data-testid="stHeading"] :is(h2, h3),
.cg-report-heading h2 {
    margin: 0;
    padding: 0;
    color: var(--cg-ink);
    font-size: clamp(1.75rem, 2.75vw, 2.65rem);
    font-weight: 800;
    letter-spacing: -.032em;
    line-height: 1.16;
}

.cg-report-heading {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: .6rem 1rem;
    min-height: 3.1rem;
}

.cg-sample-badge {
    padding: .42rem 1rem;
    border-radius: 2rem;
    background: #d0eeeb;
    color: var(--cg-ink);
    font-size: clamp(.86rem, 1.38vw, 1.33rem);
    font-weight: 550;
    white-space: nowrap;
}

.st-key-scanner_mode {
    margin-block-start: clamp(.15rem, 1.6vw, 1.5rem);
}

.st-key-scanner_mode [data-testid="stRadioGroup"] {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 0;
    align-items: stretch;
    width: 100%;
    padding: .08rem;
    border: 1px solid var(--cg-line);
    border-radius: .7rem;
    background: #f5f5f7;
}

.st-key-scanner_mode [data-testid="stRadioGroup"] > div + div {
    border-inline-start: 1px solid var(--cg-line);
}

.st-key-scanner_mode [data-testid="stRadioOption"] {
    display: flex;
    justify-content: center;
    width: 100%;
    min-height: clamp(2.65rem, 4.15vw, 3.9rem);
    margin: 0;
    padding: .35rem .28rem;
    border-radius: .58rem;
    color: var(--cg-ink);
}

.st-key-scanner_mode [data-testid="stRadioOption"][data-selected] {
    color: #fff;
    background: var(--cg-primary);
}

.st-key-scanner_mode [data-testid="stRadioOption"] > div > div:first-child {
    display: none;
}

.st-key-scanner_mode [data-testid="stRadioOption"] p {
    display: flex;
    align-items: center;
    gap: .4em;
    color: inherit;
    font-size: clamp(.87rem, 1.54vw, 1.5rem);
    font-weight: 620;
    line-height: 1.2;
    text-align: center;
}

.st-key-scanner-input [data-testid="stWidgetLabel"] p {
    color: var(--cg-ink);
    font-size: clamp(1rem, 1.7vw, 1.55rem);
    font-weight: 700;
}

.st-key-scanner-input :is([data-testid="stTextInputRootElement"], [data-testid="stTextAreaRootElement"]) {
    border: 1px solid #bfc4ca;
    border-radius: .7rem;
    background: var(--cg-surface);
}

.st-key-scanner-input [data-testid="stTextInputRootElement"] {
    min-height: clamp(2.9rem, 4.4vw, 4.15rem);
}

.st-key-scanner-input :is([data-testid="stTextInputRootElement"], [data-testid="stTextAreaRootElement"]):focus-within {
    border-color: var(--cg-focus);
    outline: 1px solid var(--cg-focus);
    outline-offset: -1px;
}

.st-key-scanner-input input:not([type="radio"]),
.st-key-scanner-input textarea {
    padding: .8rem 1rem;
    color: var(--cg-ink);
    font-size: clamp(1.07rem, 1.8vw, 1.66rem);
}

.st-key-scanner-input [data-testid="stFileUploaderDropzone"] {
    border: 1px dashed var(--cg-line);
    border-radius: .7rem;
    background: #f5f5f7;
}

.st-key-scanner-input .st-key-analyze_scan {
    margin-block-start: clamp(0rem, .6vw, .65rem);
}

.st-key-scanner-input [data-testid="stBaseButton-primary"]:enabled {
    min-height: clamp(2.85rem, 4.1vw, 3.9rem);
    border-color: var(--cg-primary);
    border-radius: .75rem;
    background: var(--cg-primary);
    color: #fff;
}

.st-key-scanner-input [data-testid="stBaseButton-primary"]:enabled:hover {
    border-color: var(--cg-primary-hover);
    background: var(--cg-primary-hover);
}

.st-key-scanner-input [data-testid="stBaseButton-primary"] p {
    font-size: clamp(1.1rem, 1.8vw, 1.68rem);
    font-weight: 720;
}

.st-key-scanner-input [data-testid="stBaseButton-secondary"],
.st-key-scanner-report [data-testid="stDownloadButton"] button {
    min-height: clamp(2.65rem, 3.84vw, 3.55rem);
    border: 1px solid #bfc3c8;
    border-radius: .7rem;
    background: var(--cg-surface);
    color: var(--cg-ink);
}

.st-key-scanner-input [data-testid="stBaseButton-secondary"] p,
.st-key-scanner-report [data-testid="stDownloadButton"] button p {
    font-size: clamp(1.03rem, 1.7vw, 1.5rem);
    font-weight: 650;
}

.st-key-scanner_mode [data-testid="stIconMaterial"],
.st-key-scanner-report [data-testid="stDownloadButton"] [data-testid="stIconMaterial"] {
    font-size: clamp(1rem, 1.9vw, 1.8rem);
}

.st-key-scanner-input [data-testid="stBaseButton-secondary"]:hover,
.st-key-scanner-report [data-testid="stDownloadButton"] button:hover {
    border-color: var(--cg-primary);
    background: #fdf1e9;
}

:is(.st-key-scanner, .st-key-cyberguard-header) :is(button:focus-visible, [data-testid="stRadioOption"][data-focus-visible]) {
    outline: 2px solid var(--cg-focus);
    outline-offset: 2px;
}

.cg-result-overview {
    display: grid;
    gap: clamp(.85rem, 1.35vw, 1.2rem);
}

.cg-verdict {
    --cg-verdict-fill: #f0f4f6;
    --cg-verdict-ink: #37536a;
    --cg-verdict-icon: #e1e9ef;
    --cg-verdict-rule: #b8cad7;
    --cg-verdict-mark: var(--cg-shield-alert);
    display: flex;
    align-items: center;
    gap: clamp(.75rem, 2vw, 1.9rem);
    padding: clamp(.9rem, 1.65vw, 1.5rem) clamp(.95rem, 2.4vw, 2.25rem);
    border-radius: .88rem;
    background: var(--cg-verdict-fill);
    color: var(--cg-verdict-ink);
}

.cg-verdict--low {
    --cg-verdict-fill: #eaf5ea;
    --cg-verdict-ink: #10702a;
    --cg-verdict-icon: #ccedcf;
    --cg-verdict-rule: #9dc9a5;
    --cg-verdict-mark: var(--cg-shield-check);
}

.cg-verdict--medium {
    --cg-verdict-fill: #fff4dc;
    --cg-verdict-ink: #89510d;
    --cg-verdict-icon: #fce7b8;
    --cg-verdict-rule: #e5bd74;
}

.cg-verdict--high {
    --cg-verdict-fill: #fcebed;
    --cg-verdict-ink: #952c38;
    --cg-verdict-icon: #f5d4d9;
    --cg-verdict-rule: #dfa2ac;
}

.cg-verdict-icon {
    display: grid;
    flex: 0 0 auto;
    place-items: center;
    width: clamp(2.85rem, 5.9vw, 5.55rem);
    aspect-ratio: 1;
    border-radius: 50%;
    background: var(--cg-verdict-icon);
}

.cg-verdict-icon::before {
    width: 63%;
    height: 63%;
    background: currentColor;
    mask: var(--cg-verdict-mark) center / contain no-repeat;
    content: "";
}

.cg-verdict-content {
    padding-inline-start: clamp(.75rem, 2.6vw, 2.4rem);
    border-inline-start: 2px solid var(--cg-verdict-rule);
}

.cg-verdict-content :is(h2, h3) {
    margin: 0;
    padding: 0;
    color: inherit;
    font-size: clamp(1.6rem, 3vw, 2.9rem);
    font-weight: 790;
    letter-spacing: -.025em;
    line-height: 1.08;
}

.cg-verdict-score {
    margin: .42rem 0 0;
    color: var(--cg-ink);
    font-size: clamp(1.05rem, 1.8vw, 1.7rem);
    font-weight: 720;
    line-height: 1.15;
}

.cg-signals {
    width: 100%;
    border: 1px solid var(--cg-line);
    border-spacing: 0;
    border-radius: .65rem;
    overflow: hidden;
    font-size: clamp(1rem, 1.53vw, 1.46rem);
    text-align: start;
}

.cg-signals :is(th, td) {
    padding: .5em .92em;
    color: var(--cg-ink);
    text-align: start;
    vertical-align: middle;
}

.cg-signals th {
    width: 31%;
    border-inline-end: 1px solid var(--cg-line);
    background: #f7f7f8;
    font-weight: 720;
}

.cg-signals tr + tr :is(th, td) {
    border-top: 1px solid var(--cg-line);
}

.cg-action {
    display: flex;
    align-items: center;
    gap: clamp(.7rem, 1.9vw, 1.7rem);
    padding: clamp(.85rem, 1.22vw, 1.12rem) clamp(.95rem, 1.9vw, 1.75rem);
    border-radius: .85rem;
    background: #fdf1d9;
}

.cg-action-icon {
    display: grid;
    flex: 0 0 auto;
    place-items: center;
    width: clamp(1.85rem, 3.75vw, 3.5rem);
    color: #8f3308;
}

.cg-action-icon::before {
    width: 100%;
    aspect-ratio: 1;
    background: currentColor;
    mask: var(--cg-shield-alert) center / contain no-repeat;
    content: "";
}

.cg-action-content {
    padding-inline-start: clamp(.65rem, 1.8vw, 1.45rem);
    border-inline-start: 2px solid #efc566;
}

.cg-action-content :is(h2, h3) {
    margin: 0 0 .28rem;
    padding: 0;
    color: #883408;
    font-size: clamp(1.12rem, 2.02vw, 1.88rem);
    font-weight: 740;
    letter-spacing: -.02em;
    line-height: 1.15;
}

.cg-action-content p {
    margin: 0;
    color: var(--cg-ink);
    font-size: clamp(1rem, 1.55vw, 1.45rem);
    line-height: 1.35;
}

.st-key-scanner-report [data-testid="stExpander"] > details {
    border-color: var(--cg-line);
    border-radius: .7rem;
}

.st-key-scanner-report [data-testid="stExpander"] > details > summary {
    min-height: 2.6rem;
    color: var(--cg-ink);
}

.st-key-scanner-report [data-testid="stExpander"]:not([data-testid="stExpander"] *) > details > summary {
    min-height: clamp(2.8rem, 4.24vw, 4rem);
}

.st-key-scanner-report [data-testid="stExpander"]:not([data-testid="stExpander"] *) > details > summary p {
    font-size: clamp(1.1rem, 1.8vw, 1.68rem);
    font-weight: 730;
}

.st-key-scanner-report [data-testid="stExpander"]:not([data-testid="stExpander"] *) > details > summary > span {
    display: flex;
    flex: 1;
    flex-direction: row-reverse;
    align-items: center;
    justify-content: space-between;
}

.st-key-scanner-report [data-testid="stExpander"]:not([data-testid="stExpander"] *) > details > summary > span > span {
    transform: none;
}

.st-key-scanner-report [data-testid="stExpander"]:not([data-testid="stExpander"] *) > details > summary [data-testid="stIconMaterial"] {
    font-size: clamp(1.25rem, 2vw, 1.9rem);
    transform: rotate(90deg);
}

.st-key-scanner-report [data-testid="stExpander"]:not([data-testid="stExpander"] *) > details[open] > summary [data-testid="stIconMaterial"] {
    transform: rotate(-90deg);
}

@media (max-width: 56rem) {
    .st-key-scanner [data-testid="stHorizontalBlock"]:has(.st-key-scanner-input):has(.st-key-scanner-report) {
        flex-direction: column;
    }

    .st-key-scanner [data-testid="stColumn"]:has(.st-key-scanner-input, .st-key-scanner-report) {
        width: 100%;
    }
}

@media (max-width: 43rem) {
    .st-key-cyberguard-header > [data-testid="stLayoutWrapper"] > [data-testid="stHorizontalBlock"] {
        flex-direction: column;
        align-items: stretch;
        gap: .2rem;
    }

    .st-key-cyberguard-header [data-testid="stColumn"] {
        width: 100%;
        min-width: 0;
    }

    .st-key-cyberguard-header [data-testid="stHorizontalBlock"] [data-testid="stHorizontalBlock"] {
        flex-wrap: nowrap;
        gap: .35rem;
    }

    .st-key-cyberguard-header [data-testid="stHorizontalBlock"] [data-testid="stHorizontalBlock"] > [data-testid="stColumn"] {
        flex: 1 1 0;
    }

    .st-key-cyberguard-header :is(.st-key-nav_scanner, .st-key-nav_history, .st-key-nav_analytics) button {
        min-height: 2.4rem;
        padding-inline: .15rem;
        border-radius: .5rem;
    }

    .st-key-cyberguard-header [data-testid="stBaseButton-primary"]::after {
        bottom: -.28rem;
    }
}

@media (max-width: 25rem) {
    .st-key-scanner_mode [data-testid="stRadioOption"] p {
        gap: .25em;
        font-size: .8rem;
    }
}
</style>
"""
