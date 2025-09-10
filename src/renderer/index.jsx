console.log('renderer loaded');
import React from 'react';
import { createRoot } from 'react-dom/client';
import App from './App';

const container = document.getElementById('root');
if (container) {
	container.innerHTML = '';
	const root = createRoot(container);
	root.render(<App />);
	console.log('React渲染已执行');
} else {
	console.error('未找到root容器');
}
