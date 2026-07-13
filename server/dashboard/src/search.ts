// ── Search & pagination state ────────────────────────────────────────────

import { $ } from './helpers';

export let page = 1;
export const PAGE_SIZE = 50;
export let searchTerm = '';
export let resultFilter = '';

let searchDebounce: ReturnType<typeof setTimeout>;

export function onSearchInput(e: Event): void {
  searchTerm = (e.target as HTMLInputElement).value.trim();
  clearTimeout(searchDebounce);
  searchDebounce = setTimeout(() => {
    page = 1;
    // refreshAll is imported and called by the api module to avoid circular deps
    document.dispatchEvent(new CustomEvent('dashboard:refresh'));
  }, 300);
}

export function onResultFilterChange(e: Event): void {
  resultFilter = (e.target as HTMLSelectElement).value;
  page = 1;
  document.dispatchEvent(new CustomEvent('dashboard:refresh'));
}

export function prevPage(): void {
  if (page > 1) {
    page--;
    document.dispatchEvent(new CustomEvent('dashboard:refresh'));
  }
}

export function nextPage(): void {
  page++;
  document.dispatchEvent(new CustomEvent('dashboard:refresh'));
}

/** Build the query log API URL with current search/filter/pagination. */
export function buildQueryLogURL(): string {
  let url = '/api/query-log?limit=' + PAGE_SIZE + '&offset=' + (page - 1) * PAGE_SIZE;
  if (searchTerm) url += '&search=' + encodeURIComponent(searchTerm);
  if (resultFilter) url += '&result=' + encodeURIComponent(resultFilter);
  return url;
}

/** Bind search input, filter select, and pagination buttons. */
export function initSearch(): void {
  const searchInput = $('search-input') as HTMLInputElement;
  searchInput.addEventListener('input', onSearchInput);

  const filterSelect = $('filter-result') as HTMLSelectElement;
  filterSelect.addEventListener('change', onResultFilterChange);

  $('btn-prev').addEventListener('click', prevPage);
  $('btn-next').addEventListener('click', nextPage);
}
