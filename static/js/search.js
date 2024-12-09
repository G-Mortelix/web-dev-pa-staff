document.getElementById('search-form').addEventListener('submit', function(event) {
    event.preventDefault();
    
    const query = document.getElementById('search-input').value;
    
    fetch(`/search?query=${encodeURIComponent(query)}`)
      .then(response => response.json())
      .then(data => {
        const resultsContainer = document.getElementById('search-results');
        resultsContainer.innerHTML = '';
        
        // Loop through departments
        for (let dept in data) {
          const deptDiv = document.createElement('div');
          deptDiv.classList.add('department');
          deptDiv.innerHTML = `<h3>${dept}</h3>`;
          
          // Loop through the folder structure of each department
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

  // Recursive function to create folder elements (with children)
  function createFolderElement(folder) {
    const folderDiv = document.createElement('div');
    folderDiv.classList.add('folder');
    folderDiv.innerHTML = `<p>${folder.name}</p>`;

    // If the folder has children, render them
    if (folder.children.length > 0) {
      const childrenDiv = document.createElement('div');
      childrenDiv.classList.add('children');
      folder.children.forEach(child => {
        childrenDiv.appendChild(createFolderElement(child));
      });
      folderDiv.appendChild(childrenDiv);
    }

    return folderDiv;
  }