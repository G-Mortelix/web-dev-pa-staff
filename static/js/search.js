document.addEventListener('DOMContentLoaded', function () {
  const searchInput = document.querySelector('input#search-input');
  console.log('Search Input:', searchInput); // Log search input element

  const departments = document.querySelectorAll('.department-container');
  console.log('Departments:', departments); // Log all department containers

  searchInput.addEventListener('input', function () {
      const query = searchInput.value.toLowerCase();
      console.log('Search Query:', query); // Log the current search query

      departments.forEach(department => {
          const folderContainers = department.querySelectorAll('[data-folder-container]');
          console.log('Folder Containers:', folderContainers); // Log all folder containers in the current department

          folderContainers.forEach(folder => {
              const folderName = folder.dataset.folderName.toLowerCase();
              console.log('Checking Folder Name:', folderName); // Log each folder's name

              if (folderName.includes(query)) {
                  console.log(`Showing folder: ${folderName}`); // Log visible folder
                  folder.style.display = '';
              } else {
                  console.log(`Hiding folder: ${folderName}`); // Log hidden folder
                  folder.style.display = 'none';
              }
          });
      });
  });
});
