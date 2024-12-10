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

      // Send the request to the /search endpoint with query and department_filter
      fetch(`/search?query=${encodeURIComponent(query)}&department_filter=${encodeURIComponent(departmentFilter)}`)
          .then(response => response.json())
          .then(data => {
              const resultsContainer = document.getElementById('search-results');
              resultsContainer.innerHTML = '';  // Clear any previous results

              // Loop through departments and create HTML for each one
              for (let dept in data) {
                  const deptDiv = document.createElement('div');
                  deptDiv.classList.add('department');
                  deptDiv.innerHTML = `<h3>${dept}</h3>`;

                  // Loop through the folder structure for each department
                  data[dept].forEach(folder => {
                      deptDiv.appendChild(createFolderElement(folder));  // Add each folder element
                  });

                  resultsContainer.appendChild(deptDiv);  // Append the department div to results container
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

// Recursive function to create folder elements (with children)
function createFolderElement(folder) {
  const folderDiv = document.createElement('div');
  folderDiv.classList.add('folder');
  folderDiv.innerHTML = `<p>${folder.name}</p>`;

  // If the folder has children, render them
  if (folder.children && folder.children.length > 0) {
      const childrenDiv = document.createElement('div');
      childrenDiv.classList.add('children');
      folder.children.forEach(child => {
          childrenDiv.appendChild(createFolderElement(child));
      });
      folderDiv.appendChild(childrenDiv);
  }

  return folderDiv;
}
