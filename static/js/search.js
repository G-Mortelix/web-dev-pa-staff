console.log("JavaScript Loaded");  // Check if JS is running

// Ensure the DOM is fully loaded before attaching the event listener
document.addEventListener('DOMContentLoaded', function () {
  const searchForm = document.getElementById('search-form');

  if (searchForm) {
    searchForm.addEventListener('submit', function(event) {
      event.preventDefault();  // Prevent the form's default behavior

      const query = document.getElementById('search-input').value;  // Get the search query
      const departmentFilter = document.querySelector('select[name="department_filter"]').value || '';
      console.log(`Sending request to /search with query: ${query}, department_filter: ${departmentFilter}`);

      fetch(`/search?query=${encodeURIComponent(query)}&department_filter=${encodeURIComponent(departmentFilter)}`)
        .then(response => response.json())
        .then(data => {
            const resultsContainer = document.getElementById('search-result');
            resultsContainer.innerHTML = '';  // Clear previous results

            // Loop through departments and render their folders
            for (let dept in data) {
                const deptDiv = document.createElement('div');
                deptDiv.classList.add('department');
                deptDiv.innerHTML = `<h3>${dept}</h3>`;

                data[dept].forEach(folder => {
                    deptDiv.appendChild(createFolderElement(folder));
                });

                resultsContainer.appendChild(deptDiv);
            }
        })
        .catch(error => {
            console.error('Error:', error);
        });

    });
  } else {
    console.error("The element with id 'search-form' was not found in the DOM.");
  }
});

function createFolderElement(folder) {
  const folderDiv = document.createElement('div');
  folderDiv.classList.add('folder');

  // Folder name and parent folder (if available)
  folderDiv.innerHTML = `
      <p><strong>Folder:</strong> ${folder.folder_name}</p>
      ${folder.parent_folder_name ? `<p><strong>Parent:</strong> ${folder.parent_folder_name}</p>` : ''}
  `;

  // PDFs in the folder
  if (folder.pdf_files && folder.pdf_files.length > 0) {
      const pdfList = document.createElement('ul');
      pdfList.classList.add('pdf-list');
      folder.pdf_files.forEach(pdf => {
          const pdfItem = document.createElement('li');
          pdfItem.innerHTML = `
              <a href="${pdf.pdf_path}" target="_blank">${pdf.pdf_name}</a>
          `;
          pdfList.appendChild(pdfItem);
      });
      folderDiv.appendChild(pdfList);
  }

  // Child folders
  if (folder.child_folders && folder.child_folders.length > 0) {
      const childFoldersDiv = document.createElement('div');
      childFoldersDiv.classList.add('children');
      folder.child_folders.forEach(child => {
          childFoldersDiv.appendChild(createFolderElement(child));
      });
      folderDiv.appendChild(childFoldersDiv);
  }

  return folderDiv;
}
