function renderProduct(product) {
	const element = document.createElement('div');
	element.classList = 'product';

	const image = document.createElement('img');
	image.src = product.imageSrc;
	image.alt = product.name;

	const wrapperWrapper = document.createElement('div');
	const wrapper = document.createElement('div');

	const name = document.createElement('div');
	name.classList = 'name';
	name.innerText = product.name;

	const description = document.createElement('div');
	description.classList = 'description';
	description.innerText = product.description;

	const priceContainer = document.createElement('div');
	priceContainer.classList = 'price-container';
	const price = document.createElement('div');
	price.classList = 'price';
	price.innerText = `$ ${Math.floor(product.price / 100)},${(product.price % 100).toString().padStart(2, '0')}`;
	const buttonLink = document.createElement('a');
	buttonLink.href = 'https://archive.org/donate';
	buttonLink.target = '_blank';
	const button = document.createElement('button');
	button.innerText = 'Buy now';
	buttonLink.appendChild(button);

	priceContainer.appendChild(price);
	priceContainer.appendChild(buttonLink);

	wrapper.appendChild(name);
	wrapper.appendChild(description);
	wrapper.appendChild(priceContainer);

	const credits = document.createElement('div');
	credits.classList = 'credits';

	const creditsLink = document.createElement('a');
	creditsLink.href = product.imageCredits;
	creditsLink.target = '_blank';
	creditsLink.innerText = 'Image credits';

	credits.appendChild(creditsLink);

	wrapperWrapper.appendChild(wrapper);
	wrapperWrapper.append(credits);

	element.appendChild(image);
	element.appendChild(wrapperWrapper);

	document.querySelector('.products').appendChild(element);
}

function renderFlag(flag) {
	const wrapper = document.createElement('div');
	wrapper.style.textAlign = 'center';
	const wordart = document.createElement('div');
	wordart.classList = 'wordart rainbow';
	wordart.setAttribute('data-flag', flag);
	const span = document.createElement('span');
	span.classList = 'text';
	span.innerText = flag;

	wordart.appendChild(span);
	wrapper.appendChild(wordart);

	const container = document.querySelector('#flagContainer');
	while (container.hasChildNodes()) {
		container.removeChild(container.lastChild);
	}
	container.appendChild(wrapper);
}

function clearProducts() {
	const container = document.querySelector('.products');
	while (container.hasChildNodes()) {
		container.removeChild(container.lastChild);
	}
}

async function search(e) {
	if (e) {
		e.preventDefault();
	}
	Clippy?.stop();
	Clippy?.play('Searching');

	clearProducts();
	const searchAnimation = document.createElement('img');
	searchAnimation.src = '/assets/images/searching.gif';
	searchAnimation.classList = 'search-animation';
	document.querySelector('.products').appendChild(searchAnimation);

	if (e) {
		await new Promise((resolve) => setTimeout(resolve, 3000));
	}

	const query = document.querySelector('#search');
	await fetch('/api/v1/csrf', {
		credentials: 'same-origin'
	});
	const res = await fetch(`/api/v1/search?name=${encodeURIComponent(query.value)}`, {
		credentials: 'same-origin'
	});
	const data = await res.json();
	clearProducts();

	if (data.error) {
		Clippy?.stop();
		Clippy?.speak(data.error);
		Clippy?.play('CheckingSomething');

		const noResult = document.createElement('em');
		noResult.style.margin = '3em 0';
		noResult.style.textAlign = 'center';
		noResult.style.display = 'block';
		noResult.innerText = 'No result found';
		document.querySelector('.products').appendChild(noResult);
	} else if (data.length !== 0) {
		data.forEach((product, idx) => {
			renderProduct(product);
			if (idx != data.length - 1) {
				document.querySelector('.products').appendChild(document.createElement('hr'));
			}
		});
	} else {
		const noResult = document.createElement('em');
		noResult.style.margin = '3em 0';
		noResult.style.textAlign = 'center';
		noResult.style.display = 'block';
		noResult.innerText = 'No result found';
		document.querySelector('.products').appendChild(noResult);
	}
}

document.querySelector('#searchForm').onsubmit = search;
