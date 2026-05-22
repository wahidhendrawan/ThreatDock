import React from 'react';

const PAGE_SIZE_OPTIONS = [50, 100, 250, 1000, 5000];

export function usePagination(items, initialPageSize = 100) {
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = React.useState(initialPageSize);
  const totalItems = Array.isArray(items) ? items.length : 0;
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize));
  const safePage = Math.min(page, totalPages);
  const start = (safePage - 1) * pageSize;
  const pagedItems = (items || []).slice(start, start + pageSize);

  React.useEffect(() => {
    setPage(1);
  }, [totalItems, pageSize]);

  return {
    page: safePage,
    setPage,
    pageSize,
    setPageSize,
    totalItems,
    totalPages,
    start,
    end: Math.min(start + pageSize, totalItems),
    pagedItems
  };
}

export default function PaginationControls({ pagination }) {
  if (!pagination || pagination.totalItems <= pagination.pageSize) {
    return null;
  }

  const canPrev = pagination.page > 1;
  const canNext = pagination.page < pagination.totalPages;

  return (
    <div className="pagination-controls">
      <div className="pagination-summary">
        Showing {pagination.start + 1}-{pagination.end} of {pagination.totalItems}
      </div>
      <div className="pagination-actions">
        <select
          className="form-select pagination-select"
          value={pagination.pageSize}
          onChange={(e) => pagination.setPageSize(Number(e.target.value))}
        >
          {PAGE_SIZE_OPTIONS.map(size => (
            <option key={size} value={size}>{size} / page</option>
          ))}
        </select>
        <button className="btn btn-outline" disabled={!canPrev} onClick={() => pagination.setPage(pagination.page - 1)}>
          Prev
        </button>
        <span className="pagination-page">Page {pagination.page} / {pagination.totalPages}</span>
        <button className="btn btn-outline" disabled={!canNext} onClick={() => pagination.setPage(pagination.page + 1)}>
          Next
        </button>
      </div>
    </div>
  );
}
