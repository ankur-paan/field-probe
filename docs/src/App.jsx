import React, { useState, useMemo, useRef, useEffect } from 'react';
import { marked } from 'marked';
import { DOCS_MANIFEST, getDocContent } from './docsData';
import {
  IconBook,
  IconShield,
  IconBinary,
  IconGitBranch,
  IconCpu,
  IconCheckCircle,
  IconActivity,
  IconBot,
  IconTerminal,
  IconGlobe,
  IconSearch
} from './icons';

// Icon resolver component
const ICON_MAP = {
  book: IconBook,
  shield: IconShield,
  binary: IconBinary,
  git: IconGitBranch,
  cpu: IconCpu,
  check: IconCheckCircle,
  activity: IconActivity,
  bot: IconBot,
  terminal: IconTerminal,
  globe: IconGlobe,
};

function DocIcon({ name, className }) {
  const Component = ICON_MAP[name] || IconBook;
  return <Component className={className || 'nav-icon'} />;
}

// Custom Marked Renderer for Technical Documentation
const renderer = new marked.Renderer();

// Custom Image renderer: wraps diagrams in an Architecture Blueprint Card
renderer.image = function (tokenOrHref, titleArg, textArg) {
  let href = '';
  let text = '';
  let title = '';

  if (typeof tokenOrHref === 'object' && tokenOrHref !== null) {
    href = tokenOrHref.href || '';
    text = tokenOrHref.text || '';
    title = tokenOrHref.title || '';
  } else {
    href = tokenOrHref || '';
    title = titleArg || '';
    text = textArg || '';
  }

  const cleanHref = (href || '')
    .replace(/^\.\/assets\//, '/assets/')
    .replace(/^assets\//, '/assets/')
    .replace(/^\.\//, '/');

  return `
    <div class="blueprint-card">
      <div class="blueprint-header">
        <span style="display:flex; align-items:center; gap:6px;">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"/>
            <line x1="3" y1="9" x2="21" y2="9"/>
            <line x1="9" y1="21" x2="9" y2="9"/>
          </svg>
          SPECIFICATION BLUEPRINT
        </span>
        <span style="font-family: var(--font-mono); font-size: 0.72rem; color: var(--text-subtle);">DIAGRAM</span>
      </div>
      <div class="blueprint-stage">
        <img src="${cleanHref}" alt="${text || 'Technical Blueprint'}" loading="lazy" />
      </div>
      ${text ? `<div class="blueprint-caption">${text}</div>` : ''}
    </div>
  `;
};

// Custom Code block renderer with dark terminal bar and copy button
renderer.code = function (tokenOrCode, infostring) {
  let code = '';
  let lang = '';
  if (typeof tokenOrCode === 'object' && tokenOrCode !== null) {
    code = tokenOrCode.text || '';
    lang = tokenOrCode.lang || '';
  } else {
    code = tokenOrCode || '';
    lang = infostring || '';
  }

  const safeCode = (code || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  return `
    <div class="code-block-wrapper">
      <div class="code-block-bar">
        <span>${lang ? lang.toUpperCase() : 'CODE'}</span>
        <button class="code-copy-btn" type="button" aria-label="Copy snippet">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>
            <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
          </svg>
          <span>Copy</span>
        </button>
      </div>
      <pre><code class="language-${lang || 'text'}">${safeCode}</code></pre>
    </div>
  `;
};

// Custom Heading renderer with anchor IDs for Table of Contents
renderer.heading = function (tokenOrText, levelArg) {
  let text = '';
  let level = 1;
  if (typeof tokenOrText === 'object' && tokenOrText !== null) {
    text = tokenOrText.text || '';
    level = tokenOrText.depth || 1;
  } else {
    text = tokenOrText || '';
    level = levelArg || 1;
  }

  const plainText = text.replace(/<[^>]*>/g, '');
  const slug = plainText
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');

  return `<h${level} id="${slug}">${text}</h${level}>`;
};

marked.setOptions({
  renderer,
  gfm: true,
  breaks: false,
});

export default function App() {
  const [selectedId, setSelectedId] = useState(DOCS_MANIFEST[0].id);
  const [searchQuery, setSearchQuery] = useState('');
  const searchInputRef = useRef(null);

  // Keyboard shortcut Ctrl/Cmd + K to focus search
  useEffect(() => {
    function handleKeyDown(e) {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        if (searchInputRef.current) {
          searchInputRef.current.focus();
        }
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const currentDocIndex = useMemo(() => {
    const idx = DOCS_MANIFEST.findIndex(d => d.id === selectedId);
    return idx >= 0 ? idx : 0;
  }, [selectedId]);

  const currentDoc = DOCS_MANIFEST[currentDocIndex] || DOCS_MANIFEST[0];

  // Raw markdown content
  const rawContent = useMemo(() => {
    return getDocContent(currentDoc.id);
  }, [currentDoc.id]);

  // Compiled HTML
  const htmlContent = useMemo(() => {
    try {
      return marked.parse(rawContent);
    } catch (err) {
      console.error('Markdown parse error:', err);
      return `<div style="color: red; padding: 20px;">Markdown parse error: ${err.message}</div>`;
    }
  }, [rawContent]);

  // Extract H2 headings for Table of Contents
  const tocHeadings = useMemo(() => {
    const matches = [];
    const lines = rawContent.split('\n');
    for (const line of lines) {
      const h2 = line.match(/^##\s+(.+)$/);
      if (h2) {
        const title = h2[1].replace(/[*_`]/g, '').trim();
        const slug = title
          .toLowerCase()
          .replace(/[^a-z0-9]+/g, '-')
          .replace(/(^-|-$)/g, '');
        matches.push({ title, slug });
      }
    }
    return matches;
  }, [rawContent]);

  // Reading time estimate
  const readingTime = useMemo(() => {
    const wordCount = rawContent.trim().split(/\s+/).length;
    const minutes = Math.max(1, Math.ceil(wordCount / 180));
    return `${minutes} min read`;
  }, [rawContent]);

  // Filtered docs for search
  const filteredDocs = useMemo(() => {
    if (!searchQuery.trim()) return DOCS_MANIFEST;
    const q = searchQuery.toLowerCase();
    return DOCS_MANIFEST.filter(
      d => d.title.toLowerCase().includes(q) || d.description.toLowerCase().includes(q)
    );
  }, [searchQuery]);

  // Group by category
  const categories = useMemo(() => {
    const cats = {};
    filteredDocs.forEach(doc => {
      if (!cats[doc.category]) cats[doc.category] = [];
      cats[doc.category].push(doc);
    });
    return cats;
  }, [filteredDocs]);

  // Event delegation for code copy button
  const handleContentClick = (e) => {
    const copyBtn = e.target.closest('.code-copy-btn');
    if (!copyBtn) return;
    const codeBlock = copyBtn.closest('.code-block-wrapper');
    const codeEl = codeBlock ? codeBlock.querySelector('code') : null;
    if (codeEl) {
      navigator.clipboard.writeText(codeEl.innerText);
      const span = copyBtn.querySelector('span');
      if (span) {
        const orig = span.textContent;
        span.textContent = 'Copied!';
        setTimeout(() => {
          span.textContent = orig;
        }, 2000);
      }
    }
  };

  const handleSelectDoc = (id) => {
    setSelectedId(id);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleTocClick = (e, slug) => {
    e.preventDefault();
    const target = document.getElementById(slug);
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  };

  return (
    <div>
      {/* Top Navigation Bar */}
      <header className="top-nav">
        <div className="brand-wrapper">
          <a
            href="#"
            className="brand-logo"
            onClick={(e) => {
              e.preventDefault();
              handleSelectDoc(DOCS_MANIFEST[0].id);
            }}
          >
            <div className="brand-icon">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
              </svg>
            </div>
            field-probe
          </a>
          <span className="badge-version">v0.1.0</span>
          <div className="badge-safety">
            <span className="live-dot" />
            <span>Tier-0 Zero-TX Verified</span>
          </div>
        </div>

        <div className="nav-actions">
          <div className="search-box">
            <IconSearch style={{ color: 'var(--text-subtle)' }} />
            <input
              ref={searchInputRef}
              type="text"
              placeholder="Search specifications..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            <span className="search-shortcut">Ctrl K</span>
          </div>

          <a
            href="https://github.com/ankur-paan/field-probe"
            target="_blank"
            rel="noopener noreferrer"
            className="github-btn"
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
              <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
            </svg>
            GitHub
          </a>
        </div>
      </header>

      {/* Main Container */}
      <div className="docs-container">
        {/* Navigation Sidebar */}
        <aside className="docs-sidebar">
          {Object.entries(categories).map(([category, docs]) => (
            <div key={category}>
              <div className="sidebar-category-title">{category}</div>
              {docs.map((doc) => (
                <button
                  key={doc.id}
                  className={`nav-link ${selectedId === doc.id ? 'active' : ''}`}
                  onClick={() => handleSelectDoc(doc.id)}
                >
                  <DocIcon name={doc.icon} />
                  <span>{doc.title}</span>
                </button>
              ))}
            </div>
          ))}
        </aside>

        {/* Center Main Article */}
        <main className="docs-main">
          <div className="article-header">
            <div className="breadcrumb-nav">
              <span>Docs</span>
              <span className="breadcrumb-sep">/</span>
              <span>{currentDoc.category}</span>
              <span className="breadcrumb-sep">/</span>
              <span style={{ color: 'var(--text-title)', fontWeight: 500 }}>{currentDoc.title}</span>
            </div>

            <div className="doc-meta-row">
              <span className="doc-reading-time">{readingTime}</span>
            </div>
          </div>

          {/* Rendered Markdown Body */}
          <article
            className="markdown-content"
            onClick={handleContentClick}
            dangerouslySetInnerHTML={{ __html: htmlContent }}
          />

          {/* Bottom Prev / Next Navigation Cards */}
          <div className="page-nav-footer">
            {currentDocIndex > 0 ? (
              <button
                className="nav-card"
                onClick={() => handleSelectDoc(DOCS_MANIFEST[currentDocIndex - 1].id)}
              >
                <span className="nav-card-label">← Previous Specification</span>
                <span className="nav-card-title">{DOCS_MANIFEST[currentDocIndex - 1].title}</span>
              </button>
            ) : <div style={{ flex: 1 }} />}

            {currentDocIndex < DOCS_MANIFEST.length - 1 ? (
              <button
                className="nav-card"
                style={{ textAlign: 'right' }}
                onClick={() => handleSelectDoc(DOCS_MANIFEST[currentDocIndex + 1].id)}
              >
                <span className="nav-card-label">Next Specification →</span>
                <span className="nav-card-title">{DOCS_MANIFEST[currentDocIndex + 1].title}</span>
              </button>
            ) : <div style={{ flex: 1 }} />}
          </div>
        </main>

        {/* Right Table of Contents */}
        <aside className="docs-toc">
          <div className="toc-title">On this page</div>
          {tocHeadings.length > 0 ? (
            <ul className="toc-list">
              {tocHeadings.map((h, i) => (
                <li key={i}>
                  <a
                    href={`#${h.slug}`}
                    className="toc-link"
                    onClick={(e) => handleTocClick(e, h.slug)}
                  >
                    {h.title}
                  </a>
                </li>
              ))}
            </ul>
          ) : (
            <p style={{ fontSize: '0.8rem', color: 'var(--text-subtle)' }}>Overview</p>
          )}
        </aside>
      </div>
    </div>
  );
}
